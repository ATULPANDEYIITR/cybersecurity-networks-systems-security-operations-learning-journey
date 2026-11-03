'use strict';

/*
 * Cryptographic hashing and integrity verification using Node.js.
 *
 * Algorithms:
 *   SHA-256, SHA-512: SHA-2 family
 *   SHA3-256, SHA3-512: SHA-3 family
 *
 * Run:
 *   node hashing.js
 *   node hashing.js hash package.zip sha256
 *   node hashing.js hash package.zip sha3-256
 *   node hashing.js verify package.zip sha256 <expected-hex-digest>
 *
 * A digest provides integrity comparison, not sender authentication.
 * Use HMAC when the verification value must be protected by a secret key.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { EventEmitter } = require('node:events');

const CHUNK_SIZE = 1024 * 1024;
const MIN_HMAC_KEY_BYTES = 32;

const ALGORITHMS = new Map([
    ['sha256', { family: 'SHA-2', bytes: 32 }],
    ['sha512', { family: 'SHA-2', bytes: 64 }],
    ['sha3-256', { family: 'SHA-3', bytes: 32 }],
    ['sha3-512', { family: 'SHA-3', bytes: 64 }]
]);

class ValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'ValidationError';
    }
}

class IntegrityError extends Error {
    constructor(message) {
        super(message);
        this.name = 'IntegrityError';
    }
}

function normalizeAlgorithm(algorithm) {
    if (typeof algorithm !== 'string') {
        throw new ValidationError('Algorithm must be a string.');
    }

    const normalized = algorithm.toLowerCase();

    if (!ALGORITHMS.has(normalized)) {
        throw new ValidationError(
            `Unsupported algorithm: ${algorithm}. ` +
            `Supported algorithms: ${[...ALGORITHMS.keys()].join(', ')}`
        );
    }

    return normalized;
}

function createHash(algorithm) {
    const normalized = normalizeAlgorithm(algorithm);

    try {
        return crypto.createHash(normalized);
    } catch (error) {
        throw new IntegrityError(
            `The runtime cannot initialize ${normalized}: ${error.message}`
        );
    }
}

function validateDigest(digest, algorithm) {
    const normalized = normalizeAlgorithm(algorithm);
    const expectedLength = ALGORITHMS.get(normalized).bytes * 2;

    if (typeof digest !== 'string') {
        throw new ValidationError('Expected digest must be a string.');
    }

    const value = digest.trim().toLowerCase();

    if (!/^[0-9a-f]+$/.test(value)) {
        throw new ValidationError(
            'Digest must contain hexadecimal characters only.'
        );
    }

    if (value.length !== expectedLength) {
        throw new ValidationError(
            `${normalized} requires ${expectedLength} hexadecimal characters.`
        );
    }

    return value;
}

function hashBuffer(data, algorithm = 'sha256') {
    if (!Buffer.isBuffer(data)) {
        throw new ValidationError('Input data must be a Buffer.');
    }

    const normalized = normalizeAlgorithm(algorithm);
    const digest = createHash(normalized).update(data).digest('hex');

    return Object.freeze({
        algorithm: normalized,
        family: ALGORITHMS.get(normalized).family,
        digest,
        byteCount: data.length,
        createdAt: new Date().toISOString()
    });
}

/*
 * Stream large files to avoid retaining the complete file in memory.
 * The async iterator propagates filesystem and stream errors to the caller.
 */
async function hashFile(filePath, algorithm = 'sha256') {
    const normalized = normalizeAlgorithm(algorithm);
    const absolutePath = path.resolve(filePath);

    const stats = await fs.promises.stat(absolutePath);

    if (!stats.isFile()) {
        throw new ValidationError('The supplied path is not a regular file.');
    }

    const hasher = createHash(normalized);
    let byteCount = 0;

    const stream = fs.createReadStream(absolutePath, {
        highWaterMark: CHUNK_SIZE
    });

    for await (const chunk of stream) {
        hasher.update(chunk);
        byteCount += chunk.length;
    }

    return Object.freeze({
        algorithm: normalized,
        family: ALGORITHMS.get(normalized).family,
        digest: hasher.digest('hex'),
        byteCount,
        createdAt: new Date().toISOString()
    });
}

function equalDigest(actualHex, expectedHex, algorithm) {
    const expected = Buffer.from(
        validateDigest(expectedHex, algorithm),
        'hex'
    );

    const actual = Buffer.from(
        validateDigest(actualHex, algorithm),
        'hex'
    );

    // timingSafeEqual requires both buffers to have identical lengths.
    return crypto.timingSafeEqual(actual, expected);
}

function verifyBuffer(data, expectedDigest, algorithm = 'sha256') {
    const normalized = normalizeAlgorithm(algorithm);
    const expected = validateDigest(expectedDigest, normalized);
    const actual = hashBuffer(data, normalized).digest;

    return equalDigest(actual, expected, normalized);
}

async function verifyFile(filePath, expectedDigest, algorithm = 'sha256') {
    const normalized = normalizeAlgorithm(algorithm);
    const expected = validateDigest(expectedDigest, normalized);
    const actual = await hashFile(filePath, normalized);

    return Object.freeze({
        valid: equalDigest(actual.digest, expected, normalized),
        algorithm: normalized,
        expectedDigest: expected,
        actualDigest: actual.digest,
        byteCount: actual.byteCount
    });
}

function createHmac(data, key, algorithm = 'sha256') {
    if (!Buffer.isBuffer(data) || !Buffer.isBuffer(key)) {
        throw new ValidationError('HMAC data and key must be Buffers.');
    }

    if (key.length < MIN_HMAC_KEY_BYTES) {
        throw new ValidationError(
            `HMAC keys must contain at least ${MIN_HMAC_KEY_BYTES} bytes.`
        );
    }

    const normalized = normalizeAlgorithm(algorithm);

    return crypto
        .createHmac(normalized, key)
        .update(data)
        .digest('hex');
}

function verifyHmac(data, key, expectedTag, algorithm = 'sha256') {
    const normalized = normalizeAlgorithm(algorithm);
    const expected = validateDigest(expectedTag, normalized);
    const actual = createHmac(data, key, normalized);

    return equalDigest(actual, expected, normalized);
}

class IntegrityMonitor extends EventEmitter {
    /*
     * The registry stores immutable metadata rather than retaining file
     * contents. A new manifest is created for each registered release.
     */
    constructor() {
        super();
        this.manifests = new Map();
    }

    async register(filePath, algorithm = 'sha256') {
        const normalized = normalizeAlgorithm(algorithm);
        const result = await hashFile(filePath, normalized);
        const id = crypto.randomUUID();

        const manifest = Object.freeze({
            id,
            fileName: path.basename(filePath),
            algorithm: normalized,
            digest: result.digest,
            byteCount: result.byteCount,
            createdAt: new Date().toISOString()
        });

        this.manifests.set(id, manifest);
        this.emit('registered', manifest);

        return manifest;
    }

    async verify(id, filePath) {
        const manifest = this.manifests.get(id);

        if (!manifest) {
            throw new IntegrityError(`Manifest ${id} was not found.`);
        }

        const result = await hashFile(filePath, manifest.algorithm);

        const byteCountMatches = result.byteCount === manifest.byteCount;
        const digestMatches = equalDigest(
            result.digest,
            manifest.digest,
            manifest.algorithm
        );

        const valid = byteCountMatches && digestMatches;

        const verification = Object.freeze({
            manifestId: id,
            fileName: manifest.fileName,
            valid,
            byteCountMatches,
            expectedDigest: manifest.digest,
            actualDigest: result.digest,
            checkedAt: new Date().toISOString()
        });

        this.emit(valid ? 'verified' : 'mismatch', verification);

        return verification;
    }

    getManifest(id) {
        return this.manifests.get(id) ?? null;
    }
}

function runKnownAnswerTests() {
    const vectors = [
        {
            algorithm: 'sha256',
            input: '',
            expected:
                'e3b0c44298fc1c149afbf4c8996fb924' +
                '27ae41e4649b934ca495991b7852b855'
        },
        {
            algorithm: 'sha3-256',
            input: '',
            expected:
                'a7ffc6f8bf1ed76651c14756a061d662' +
                'f580ff4de43b49fa82d80a4b80f8434a'
        },
        {
            algorithm: 'sha256',
            input: 'abc',
            expected:
                'ba7816bf8f01cfea414140de5dae2223' +
                'b00361a396177a9cb410ff61f20015ad'
        },
        {
            algorithm: 'sha3-256',
            input: 'abc',
            expected:
                '3a985da74fe225b2045c172d6bd390bd' +
                '855f086e3e9d525b46bfe24511431532'
        }
    ];

    for (const vector of vectors) {
        const actual = hashBuffer(
            Buffer.from(vector.input, 'utf8'),
            vector.algorithm
        ).digest;

        if (actual !== vector.expected) {
            throw new IntegrityError(
                `Known-answer test failed for ${vector.algorithm}.`
            );
        }
    }
}

async function runDemonstration() {
    runKnownAnswerTests();

    const monitor = new IntegrityMonitor();

    monitor.on('registered', manifest => {
        console.log(`Registered: ${manifest.fileName}`);
    });

    monitor.on('verified', result => {
        console.log(`Verified: ${result.fileName}`);
    });

    monitor.on('mismatch', result => {
        console.log(`MISMATCH: ${result.fileName}`);
    });

    const payload = Buffer.from(
        'Release package: version 2.4.1\n' +
        'Component: payment-service\n' +
        'Environment: production\n',
        'utf8'
    );

    console.log('\nDigest comparison');

    for (const algorithm of ALGORITHMS.keys()) {
        const result = hashBuffer(payload, algorithm);
        console.log(`${algorithm.padEnd(9)} ${result.digest}`);
    }

    const temporaryDirectory = await fs.promises.mkdtemp(
        path.join(require('node:os').tmpdir(), 'hashing-lab-')
    );

    const artifactPath = path.join(
        temporaryDirectory,
        'release-package.txt'
    );

    try {
        await fs.promises.writeFile(artifactPath, payload);

        const manifest = await monitor.register(
            artifactPath,
            'sha3-256'
        );

        const firstCheck = await monitor.verify(
            manifest.id,
            artifactPath
        );

        console.log(`Initial integrity result: ${firstCheck.valid}`);

        await fs.promises.appendFile(
            artifactPath,
            'unauthorized modification\n'
        );

        const secondCheck = await monitor.verify(
            manifest.id,
            artifactPath
        );

        console.log(`After modification: ${secondCheck.valid}`);

        const hmacKey = crypto.randomBytes(MIN_HMAC_KEY_BYTES);
        const tag = createHmac(payload, hmacKey, 'sha256');

        console.log(
            `Valid HMAC: ${verifyHmac(payload, hmacKey, tag, 'sha256')}`
        );

        console.log(
            `Modified HMAC: ${
                verifyHmac(
                    Buffer.concat([payload, Buffer.from('changed')]),
                    hmacKey,
                    tag,
                    'sha256'
                )
            }`
        );

        console.log('\nKnown-answer tests: PASSED');
    } finally {
        await fs.promises.rm(temporaryDirectory, {
            recursive: true,
            force: true
        });
    }
}

async function runCommandLine() {
    const [, , command, ...args] = process.argv;

    if (!command) {
        await runDemonstration();
        return 0;
    }

    if (command === 'hash') {
        const [filePath, algorithm = 'sha256'] = args;

        if (!filePath) {
            throw new ValidationError(
                'Usage: node hashing.js hash <file> [algorithm]'
            );
        }

        const result = await hashFile(filePath, algorithm);

        console.log(`Algorithm: ${result.algorithm}`);
        console.log(`Bytes: ${result.byteCount}`);
        console.log(`Digest: ${result.digest}`);

        return 0;
    }

    if (command === 'verify') {
        const [filePath, algorithm, expectedDigest] = args;

        if (!filePath || !algorithm || !expectedDigest) {
            throw new ValidationError(
                'Usage: node hashing.js verify <file> <algorithm> <digest>'
            );
        }

        const result = await verifyFile(
            filePath,
            expectedDigest,
            algorithm
        );

        console.log(result.valid ? 'INTEGRITY VERIFIED' : 'INTEGRITY MISMATCH');

        return result.valid ? 0 : 1;
    }

    throw new ValidationError(`Unknown command: ${command}`);
}

runCommandLine()
    .then(exitCode => {
        process.exitCode = exitCode;
    })
    .catch(error => {
        console.error(`${error.name}: ${error.message}`);
        process.exitCode = 2;
    });
