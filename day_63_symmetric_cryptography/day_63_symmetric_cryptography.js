'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const { EventEmitter } = require('node:events');

const ALGORITHMS = Object.freeze({
    RSA: 'RSA',
    ECC: 'ECC'
});

class CryptoValidationError extends Error {}

function validateBuffer(value, name) {
    if (!Buffer.isBuffer(value)) {
        throw new CryptoValidationError(`${name} must be a Buffer`);
    }
    if (value.length === 0) {
        throw new CryptoValidationError(`${name} cannot be empty`);
    }
}

function fingerprint(publicKey) {
    return crypto
        .createHash('sha256')
        .update(publicKey.export({ type: 'spki', format: 'der' }))
        .digest('hex');
}

class KeyRegistry {
    #keys = new Map();

    register(id, keyPair) {
        if (!id || this.#keys.has(id)) {
            throw new CryptoValidationError('Key identifier must be unique');
        }

        const publicKey = keyPair.publicKey;
        this.#keys.set(id, {
            algorithm: keyPair.algorithm,
            publicKey,
            privateKey: keyPair.privateKey,
            fingerprint: fingerprint(publicKey)
        });
    }

    get(id) {
        const entry = this.#keys.get(id);
        if (!entry) {
            throw new CryptoValidationError(`Unknown key: ${id}`);
        }
        return entry;
    }

    list() {
        return [...this.#keys.entries()].map(([id, entry]) => ({
            id,
            algorithm: entry.algorithm,
            fingerprint: entry.fingerprint
        }));
    }
}

class RepositoryCryptoService extends EventEmitter {
    #registry;

    constructor(registry) {
        super();
        this.#registry = registry;
    }

    async sign(keyId, payload) {
        validateBuffer(payload, 'payload');
        const key = this.#registry.get(keyId);

        let signature;
        if (key.algorithm === ALGORITHMS.RSA) {
            const signer = crypto.createSign('SHA256');
            signer.update(payload);
            signer.end();
            signature = signer.sign({
                key: key.privateKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
            });
        } else {
            const signer = crypto.createSign('SHA256');
            signer.update(payload);
            signer.end();
            signature = signer.sign(key.privateKey);
        }

        this.emit('operation', {
            type: 'sign',
            keyId,
            algorithm: key.algorithm,
            success: true
        });

        return signature;
    }

    async verify(keyId, payload, signature) {
        validateBuffer(payload, 'payload');
        validateBuffer(signature, 'signature');

        const key = this.#registry.get(keyId);
        const verifier = crypto.createVerify('SHA256');
        verifier.update(payload);
        verifier.end();

        const options = key.algorithm === ALGORITHMS.RSA
            ? {
                key: key.publicKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
            }
            : { key: key.publicKey };

        const valid = verifier.verify(options, signature);

        this.emit('operation', {
            type: 'verify',
            keyId,
            algorithm: key.algorithm,
            success: valid
        });

        return valid;
    }

    async encryptForRecipient(keyId, plaintext) {
        validateBuffer(plaintext, 'plaintext');
        const key = this.#registry.get(keyId);

        if (key.algorithm !== ALGORITHMS.RSA) {
            throw new CryptoValidationError(
                'Direct public-key encryption in this example requires RSA'
            );
        }

        const ciphertext = crypto.publicEncrypt(
            {
                key: key.publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            plaintext
        );

        this.emit('operation', {
            type: 'encrypt',
            keyId,
            algorithm: key.algorithm,
            success: true
        });

        return ciphertext;
    }
}

function generateKeys() {
    const rsa = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicExponent: 0x10001
    });

    const ec = crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1'
    });

    return { rsa, ec };
}

async function main() {
    const { rsa, ec } = generateKeys();
    const registry = new KeyRegistry();

    registry.register('release-rsa', {
        algorithm: ALGORITHMS.RSA,
        publicKey: rsa.publicKey,
        privateKey: rsa.privateKey
    });

    registry.register('release-ecc', {
        algorithm: ALGORITHMS.ECC,
        publicKey: ec.publicKey,
        privateKey: ec.privateKey
    });

    const service = new RepositoryCryptoService(registry);

    service.on('operation', event => {
        console.log(
            `[EVENT] ${event.type} key=${event.keyId} ` +
            `algorithm=${event.algorithm} success=${event.success}`
        );
    });

    const manifest = Buffer.from(
        JSON.stringify({
            repository: 'secure-release-service',
            version: '4.2.0',
            artifact: 'release.tar.gz',
            timestamp: new Date().toISOString()
        })
    );

    const encrypted = await service.encryptForRecipient(
        'release-rsa',
        Buffer.from('release-secret')
    );

    console.log('Encrypted secret length:', encrypted.length);

    const rsaSignature = await service.sign('release-rsa', manifest);
    console.log(
        'RSA verification:',
        await service.verify('release-rsa', manifest, rsaSignature)
    );

    const changedManifest = Buffer.from(
        manifest.toString().replace('4.2.0', '4.2.1')
    );

    console.log(
        'Tampered RSA verification:',
        await service.verify('release-rsa', changedManifest, rsaSignature)
    );

    const eccSignature = await service.sign('release-ecc', manifest);
    console.log(
        'ECC verification:',
        await service.verify('release-ecc', manifest, eccSignature)
    );

    console.table(registry.list());

    const audit = {
        generatedAt: new Date().toISOString(),
        keys: registry.list(),
        encryptedBytes: encrypted.length
    };

    await fs.writeFile(
        'crypto-audit.json',
        JSON.stringify(audit, null, 2),
        { encoding: 'utf8', mode: 0o600 }
    );

    try {
        await service.encryptForRecipient(
            'release-rsa',
            Buffer.alloc(300)
        );
    } catch (error) {
        console.log('Expected encryption-size failure:', error.message);
    }
}

main().catch(error => {
    console.error('Fatal error:', error.message);
    process.exitCode = 1;
});
