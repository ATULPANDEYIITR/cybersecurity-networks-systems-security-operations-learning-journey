'use strict';

/*
 * Cryptography Fundamentals
 * Plaintext, ciphertext, keys, symmetric encryption, and asymmetric encryption.
 *
 * The implementation uses Node.js standard-library facilities where possible.
 * XOR is included to expose symmetric-key mechanics, while AES-256-GCM,
 * SHA-256, HMAC, and RSA are implemented using Node's crypto module.
 *
 * Production encryption should use authenticated encryption and established
 * cryptographic APIs rather than custom cryptographic algorithms.
 */

const crypto = require('node:crypto');

class CryptoError extends Error {
    constructor(message) {
        super(message);
        this.name = 'CryptoError';
    }
}

function requireCondition(condition, message) {
    if (!condition) {
        throw new CryptoError(message);
    }
}

function validatePlaintext(plaintext) {
    requireCondition(typeof plaintext === 'string', 'Plaintext must be a string.');
    requireCondition(plaintext.length > 0, 'Plaintext must not be empty.');
    requireCondition(plaintext.length <= 1_048_576, 'Plaintext is too large.');
}

function caesarTransform(text, shift) {
    validatePlaintext(text);
    const normalizedShift = ((shift % 26) + 26) % 26;

    return [...text].map(character => {
        const code = character.charCodeAt(0);

        if (code >= 65 && code <= 90) {
            return String.fromCharCode(
                ((code - 65 + normalizedShift) % 26) + 65
            );
        }

        if (code >= 97 && code <= 122) {
            return String.fromCharCode(
                ((code - 97 + normalizedShift) % 26) + 97
            );
        }

        return character;
    }).join('');
}

function caesarEncrypt(plaintext, shift) {
    return caesarTransform(plaintext, shift);
}

function caesarDecrypt(ciphertext, shift) {
    return caesarTransform(ciphertext, -shift);
}

function xorCipher(buffer, key) {
    requireCondition(Buffer.isBuffer(buffer), 'XOR input must be a Buffer.');
    requireCondition(Buffer.isBuffer(key), 'XOR key must be a Buffer.');
    requireCondition(key.length >= 16, 'XOR demonstration key must be at least 16 bytes.');

    const result = Buffer.allocUnsafe(buffer.length);

    for (let i = 0; i < buffer.length; i++) {
        result[i] = buffer[i] ^ key[i % key.length];
    }

    return result;
}

function createSymmetricKey() {
    return crypto.randomBytes(32);
}

function keyFingerprint(key) {
    return crypto
        .createHash('sha256')
        .update(key)
        .digest('hex')
        .slice(0, 16);
}

function createHmac(message, key) {
    requireCondition(key.length >= 16, 'HMAC key must be at least 16 bytes.');

    return crypto
        .createHmac('sha256', key)
        .update(message)
        .digest();
}

function constantTimeEqual(a, b) {
    if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b) || a.length !== b.length) {
        return false;
    }

    return crypto.timingSafeEqual(a, b);
}

function aesGcmEncrypt(plaintext, key) {
    requireCondition(key.length === 32, 'AES-256 requires a 32-byte key.');

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    const ciphertext = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final()
    ]);

    const authTag = cipher.getAuthTag();

    return { iv, ciphertext, authTag };
}

function aesGcmDecrypt(packet, key) {
    requireCondition(key.length === 32, 'AES-256 requires a 32-byte key.');

    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        packet.iv
    );

    decipher.setAuthTag(packet.authTag);

    return Buffer.concat([
        decipher.update(packet.ciphertext),
        decipher.final()
    ]).toString('utf8');
}

function generateRsaKeyPair() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicExponent: 0x10001,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
}

function rsaEncrypt(plaintext, publicKey) {
    return crypto.publicEncrypt(
        {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        Buffer.from(plaintext, 'utf8')
    );
}

function rsaDecrypt(ciphertext, privateKey) {
    return crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        ciphertext
    ).toString('utf8');
}

function demonstrateBasics() {
    console.log('=== 1. Plaintext and Ciphertext ===');

    const plaintext = 'Meet at 10:30';
    const ciphertext = caesarEncrypt(plaintext, 7);
    const recovered = caesarDecrypt(ciphertext, 7);

    console.log(`Plaintext : ${plaintext}`);
    console.log(`Ciphertext: ${ciphertext}`);
    console.log(`Recovered : ${recovered}`);

    requireCondition(recovered === plaintext, 'Caesar round trip failed.');
}

function demonstrateXorAndIntegrity() {
    console.log('\n=== 2. Symmetric-Key Mechanics ===');

    const plaintext = Buffer.from(
        'Shared-secret encryption uses one secret for both directions.',
        'utf8'
    );

    const encryptionKey = createSymmetricKey();
    const authenticationKey = createSymmetricKey();

    const ciphertext = xorCipher(plaintext, encryptionKey);
    const recovered = xorCipher(ciphertext, encryptionKey);

    console.log(`Encryption key fingerprint: ${keyFingerprint(encryptionKey)}`);
    console.log(`Ciphertext: ${ciphertext.toString('hex')}`);
    console.log(`Recovered : ${recovered.toString('utf8')}`);

    requireCondition(
        recovered.equals(plaintext),
        'XOR round trip failed.'
    );

    const tag = createHmac(ciphertext, authenticationKey);

    requireCondition(
        constantTimeEqual(
            createHmac(ciphertext, authenticationKey),
            tag
        ),
        'HMAC verification failed.'
    );

    const tampered = Buffer.from(ciphertext);
    tampered[0] ^= 0x01;

    requireCondition(
        !constantTimeEqual(
            createHmac(tampered, authenticationKey),
            tag
        ),
        'Tampering was not detected.'
    );

    console.log('HMAC verification: valid');
    console.log('Tampering detection: valid');
}

function demonstrateProductionSymmetricEncryption() {
    console.log('\n=== 3. AES-256-GCM ===');

    const key = createSymmetricKey();
    const plaintext = 'Production-oriented authenticated encryption example.';

    const packet = aesGcmEncrypt(plaintext, key);
    const recovered = aesGcmDecrypt(packet, key);

    console.log(`Key fingerprint: ${keyFingerprint(key)}`);
    console.log(`IV: ${packet.iv.toString('hex')}`);
    console.log(`Ciphertext: ${packet.ciphertext.toString('hex')}`);
    console.log(`Authentication tag: ${packet.authTag.toString('hex')}`);
    console.log(`Recovered: ${recovered}`);

    requireCondition(recovered === plaintext, 'AES-GCM round trip failed.');

    const tamperedPacket = {
        iv: Buffer.from(packet.iv),
        ciphertext: Buffer.from(packet.ciphertext),
        authTag: Buffer.from(packet.authTag)
    };

    tamperedPacket.ciphertext[0] ^= 0x01;

    try {
        aesGcmDecrypt(tamperedPacket, key);
        throw new CryptoError('Tampered AES-GCM ciphertext was accepted.');
    } catch (error) {
        if (error instanceof CryptoError) {
            throw error;
        }
        console.log('AES-GCM detected ciphertext tampering.');
    }
}

function demonstrateAsymmetricEncryption() {
    console.log('\n=== 4. RSA-OAEP ===');

    const { publicKey, privateKey } = generateRsaKeyPair();
    const plaintext = 'The public key can encrypt without exposing the private key.';

    const ciphertext = rsaEncrypt(plaintext, publicKey);
    const recovered = rsaDecrypt(ciphertext, privateKey);

    console.log(`Ciphertext length: ${ciphertext.length} bytes`);
    console.log(`Recovered: ${recovered}`);

    requireCondition(recovered === plaintext, 'RSA round trip failed.');

    const wrongPair = generateRsaKeyPair();

    try {
        rsaDecrypt(ciphertext, wrongPair.privateKey);
        throw new CryptoError('RSA accepted an unrelated private key.');
    } catch (error) {
        if (error instanceof CryptoError) {
            throw error;
        }
        console.log('Unrelated RSA private key rejected.');
    }
}

async function demonstrateAsyncPolicyEvaluation() {
    console.log('\n=== 5. Event-Driven Policy Evaluation ===');

    const events = [
        { type: 'KEY_CREATED', owner: 'service-a', algorithm: 'AES-256-GCM' },
        { type: 'ENCRYPTION_REQUESTED', owner: 'service-a', dataClass: 'confidential' },
        { type: 'KEY_CREATED', owner: 'service-b', algorithm: 'RSA-2048' },
        { type: 'ENCRYPTION_REQUESTED', owner: 'service-b', dataClass: 'restricted' }
    ];

    const allowedAlgorithms = new Set(['AES-256-GCM', 'RSA-2048']);

    const results = await Promise.all(
        events.map(async event => {
            await new Promise(resolve => setImmediate(resolve));

            if (event.type === 'KEY_CREATED') {
                return {
                    event,
                    allowed: allowedAlgorithms.has(event.algorithm),
                    reason: allowedAlgorithms.has(event.algorithm)
                        ? 'Approved algorithm'
                        : 'Algorithm is not permitted'
                };
            }

            return {
                event,
                allowed: true,
                reason: 'Event requires encryption policy evaluation'
            };
        })
    );

    for (const result of results) {
        console.log(
            `${result.event.type}: ${result.allowed ? 'allowed' : 'blocked'} - ${result.reason}`
        );
    }
}

function demonstrateFailureConditions() {
    console.log('\n=== 6. Failure Conditions ===');

    try {
        xorCipher(Buffer.from('data'), Buffer.from('short'));
    } catch (error) {
        console.log(`Short key rejected: ${error.message}`);
    }

    try {
        aesGcmDecrypt(
            {
                iv: crypto.randomBytes(12),
                ciphertext: Buffer.from('invalid'),
                authTag: crypto.randomBytes(16)
            },
            createSymmetricKey()
        );
    } catch (error) {
        console.log('Invalid authenticated ciphertext rejected.');
    }

    const samples = new Map([
        ['empty-string', ''],
        ['unicode', 'Confidential नमस्ते'],
        ['large-shift', 'Abc XYZ']
    ]);

    requireCondition(
        samples.get('empty-string') === '',
        'Empty-string classification failed.'
    );

    const unicode = samples.get('unicode');
    const encryptedUnicode = caesarEncrypt(unicode, 3);

    requireCondition(
        caesarDecrypt(encryptedUnicode, 3) === unicode,
        'Unicode handling failed.'
    );

    requireCondition(
        caesarDecrypt(caesarEncrypt(samples.get('large-shift'), 52), 52) ===
        samples.get('large-shift'),
        'Shift normalization failed.'
    );

    console.log('Edge-case validation completed.');
}

async function main() {
    demonstrateBasics();
    demonstrateXorAndIntegrity();
    demonstrateProductionSymmetricEncryption();
    demonstrateAsymmetricEncryption();
    await demonstrateAsyncPolicyEvaluation();
    demonstrateFailureConditions();

    console.log('\nCryptography demonstrations completed successfully.');
}

main().catch(error => {
    console.error(`Fatal error: ${error.message}`);
    process.exitCode = 1;
});
