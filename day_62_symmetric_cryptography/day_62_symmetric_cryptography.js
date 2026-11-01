'use strict';

/*
 * Symmetric cryptography case study using Node.js standard-library crypto.
 *
 * Covers:
 * - AES-256-GCM authenticated encryption
 * - AES-CBC with HMAC
 * - AES-CTR with HMAC
 * - IV/nonce generation and validation
 * - associated authenticated data
 * - key rotation
 * - password-derived key wrapping with scrypt
 * - tamper detection
 * - event-driven encryption audit
 *
 * Run with:
 *   node symmetric_crypto.js
 */

const crypto = require('crypto');
const { EventEmitter } = require('events');

const AES_KEY_BYTES = 32;
const GCM_IV_BYTES = 12;
const CBC_IV_BYTES = 16;
const CTR_IV_BYTES = 16;
const GCM_TAG_BYTES = 16;

class CryptoValidationError extends Error {}
class IntegrityError extends Error {}

function requireBuffer(value, name) {
    if (!Buffer.isBuffer(value)) {
        throw new CryptoValidationError(`${name} must be a Buffer`);
    }
}

function randomBytes(length) {
    return crypto.randomBytes(length);
}

function deriveKey(password, salt, length = AES_KEY_BYTES) {
    requireBuffer(salt, 'salt');

    if (typeof password !== 'string' || password.length < 12) {
        throw new CryptoValidationError(
            'Password must contain at least 12 characters'
        );
    }

    return crypto.scryptSync(
        password,
        salt,
        length,
        {
            N: 16384,
            r: 8,
            p: 1,
            maxmem: 64 * 1024 * 1024
        }
    );
}

function aesGcmEncrypt(key, plaintext, aad = Buffer.alloc(0)) {
    requireBuffer(key, 'key');
    requireBuffer(plaintext, 'plaintext');
    requireBuffer(aad, 'aad');

    if (key.length !== AES_KEY_BYTES) {
        throw new CryptoValidationError('AES-256 requires a 32-byte key');
    }

    const iv = randomBytes(GCM_IV_BYTES);
    const cipher = crypto.createCipheriv(
        'aes-256-gcm',
        key,
        iv
    );

    cipher.setAAD(aad);

    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
    ]);

    const tag = cipher.getAuthTag();

    return {
        algorithm: 'AES-256-GCM',
        iv,
        ciphertext,
        tag,
        aad
    };
}

function aesGcmDecrypt(key, envelope) {
    requireBuffer(key, 'key');

    if (envelope.iv.length !== GCM_IV_BYTES) {
        throw new CryptoValidationError('GCM IV must be 12 bytes');
    }

    if (envelope.tag.length !== GCM_TAG_BYTES) {
        throw new CryptoValidationError('GCM tag must be 16 bytes');
    }

    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        envelope.iv
    );

    decipher.setAAD(envelope.aad);
    decipher.setAuthTag(envelope.tag);

    try {
        return Buffer.concat([
            decipher.update(envelope.ciphertext),
            decipher.final()
        ]);
    } catch {
        throw new IntegrityError(
            'AES-GCM authentication failed'
        );
    }
}

function hmacSha256(key, data) {
    return crypto
        .createHmac('sha256', key)
        .update(data)
        .digest();
}

function constantTimeEqual(left, right) {
    if (left.length !== right.length) {
        return false;
    }

    return crypto.timingSafeEqual(left, right);
}

function aesCbcHmacEncrypt(encryptionKey, macKey, plaintext) {
    const iv = randomBytes(CBC_IV_BYTES);

    const cipher = crypto.createCipheriv(
        'aes-256-cbc',
        encryptionKey,
        iv
    );

    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
    ]);

    const authenticatedData = Buffer.concat([
        Buffer.from('AES-CBC-HMAC-v1'),
        iv,
        ciphertext
    ]);

    const tag = hmacSha256(
        macKey,
        authenticatedData
    );

    return {
        algorithm: 'AES-256-CBC-HMAC-SHA256',
        iv,
        ciphertext,
        tag
    };
}

function aesCbcHmacDecrypt(encryptionKey, macKey, envelope) {
    const authenticatedData = Buffer.concat([
        Buffer.from('AES-CBC-HMAC-v1'),
        envelope.iv,
        envelope.ciphertext
    ]);

    const expectedTag = hmacSha256(
        macKey,
        authenticatedData
    );

    if (!constantTimeEqual(expectedTag, envelope.tag)) {
        throw new IntegrityError(
            'CBC integrity validation failed'
        );
    }

    try {
        const decipher = crypto.createDecipheriv(
            'aes-256-cbc',
            encryptionKey,
            envelope.iv
        );

        return Buffer.concat([
            decipher.update(envelope.ciphertext),
            decipher.final()
        ]);
    } catch {
        throw new IntegrityError(
            'CBC ciphertext could not be decrypted'
        );
    }
}

function aesCtrHmacEncrypt(encryptionKey, macKey, plaintext) {
    const iv = randomBytes(CTR_IV_BYTES);

    const cipher = crypto.createCipheriv(
        'aes-256-ctr',
        encryptionKey,
        iv
    );

    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
    ]);

    const tag = hmacSha256(
        macKey,
        Buffer.concat([
            Buffer.from('AES-CTR-HMAC-v1'),
            iv,
            ciphertext
        ])
    );

    return {
        algorithm: 'AES-256-CTR-HMAC-SHA256',
        iv,
        ciphertext,
        tag
    };
}

function aesCtrHmacDecrypt(encryptionKey, macKey, envelope) {
    const expectedTag = hmacSha256(
        macKey,
        Buffer.concat([
            Buffer.from('AES-CTR-HMAC-v1'),
            envelope.iv,
            envelope.ciphertext
        ])
    );

    if (!constantTimeEqual(expectedTag, envelope.tag)) {
        throw new IntegrityError(
            'CTR integrity validation failed'
        );
    }

    const decipher = crypto.createDecipheriv(
        'aes-256-ctr',
        encryptionKey,
        envelope.iv
    );

    return Buffer.concat([
        decipher.update(envelope.ciphertext),
        decipher.final()
    ]);
}

class KeyManager extends EventEmitter {
    constructor() {
        super();
        this.keys = new Map();
        this.activeKeyId = null;
    }

    generateKey() {
        const keyId = crypto.randomUUID();

        const record = {
            keyId,
            key: randomBytes(AES_KEY_BYTES),
            createdAt: new Date().toISOString(),
            status: 'ACTIVE'
        };

        if (this.activeKeyId) {
            const previous = this.keys.get(this.activeKeyId);
            previous.status = 'RETIRED';
        }

        this.keys.set(keyId, record);
        this.activeKeyId = keyId;

        this.emit('keyRotated', {
            keyId,
            createdAt: record.createdAt
        });

        return this.publicMetadata(record);
    }

    getActiveKey() {
        if (!this.activeKeyId) {
            throw new CryptoValidationError(
                'No active encryption key exists'
            );
        }

        return this.getKey(this.activeKeyId);
    }

    getKey(keyId) {
        const record = this.keys.get(keyId);

        if (!record) {
            throw new CryptoValidationError(
                'Unknown key identifier'
            );
        }

        if (record.status !== 'ACTIVE') {
            throw new CryptoValidationError(
                'Key is not active'
            );
        }

        return record.key;
    }

    publicMetadata(record) {
        return {
            keyId: record.keyId,
            createdAt: record.createdAt,
            status: record.status
        };
    }
}

function wrapKey(dataKey, password) {
    const salt = randomBytes(16);
    const wrappingKey = deriveKey(password, salt);

    const envelope = aesGcmEncrypt(
        wrappingKey,
        dataKey,
        Buffer.from('key-wrap-v1')
    );

    return {
        version: 1,
        kdf: 'scrypt',
        salt: salt.toString('base64'),
        iv: envelope.iv.toString('base64'),
        ciphertext: envelope.ciphertext.toString('base64'),
        tag: envelope.tag.toString('base64')
    };
}

function unwrapKey(record, password) {
    const salt = Buffer.from(record.salt, 'base64');
    const wrappingKey = deriveKey(password, salt);

    return aesGcmDecrypt(
        wrappingKey,
        {
            iv: Buffer.from(record.iv, 'base64'),
            ciphertext: Buffer.from(record.ciphertext, 'base64'),
            tag: Buffer.from(record.tag, 'base64'),
            aad: Buffer.from('key-wrap-v1')
        }
    );
}

function runTests() {
    const keyManager = new KeyManager();
    const audit = [];

    keyManager.on('keyRotated', event => {
        audit.push({
            event: 'KEY_ROTATED',
            ...event
        });
    });

    keyManager.generateKey();

    const key = keyManager.getActiveKey();
    const plaintext = Buffer.from(
        'Confidential repository deployment configuration'
    );
    const aad = Buffer.from(
        'repository=payments;record=42'
    );

    const gcm = aesGcmEncrypt(key, plaintext, aad);
    const recovered = aesGcmDecrypt(key, gcm);

    if (!recovered.equals(plaintext)) {
        throw new Error('GCM round-trip failed');
    }

    const tampered = {
        ...gcm,
        ciphertext: Buffer.from(gcm.ciphertext)
    };

    tampered.ciphertext[0] ^= 0x01;

    try {
        aesGcmDecrypt(key, tampered);
        throw new Error('Tampering was not detected');
    } catch (error) {
        if (!(error instanceof IntegrityError)) {
            throw error;
        }
    }

    const encryptionKey = randomBytes(AES_KEY_BYTES);
    const macKey = randomBytes(AES_KEY_BYTES);

    const cbc = aesCbcHmacEncrypt(
        encryptionKey,
        macKey,
        plaintext
    );

    if (!aesCbcHmacDecrypt(
        encryptionKey,
        macKey,
        cbc
    ).equals(plaintext)) {
        throw new Error('CBC/HMAC round-trip failed');
    }

    const ctr = aesCtrHmacEncrypt(
        encryptionKey,
        macKey,
        plaintext
    );

    if (!aesCtrHmacDecrypt(
        encryptionKey,
        macKey,
        ctr
    ).equals(plaintext)) {
        throw new Error('CTR/HMAC round-trip failed');
    }

    const wrapped = wrapKey(
        key,
        'correct horse battery staple'
    );

    if (!unwrapKey(
        wrapped,
        'correct horse battery staple'
    ).equals(key)) {
        throw new Error('Key wrapping failed');
    }

    console.log('AES-GCM round-trip: PASS');
    console.log('AES-GCM tamper detection: PASS');
    console.log('AES-CBC-HMAC round-trip: PASS');
    console.log('AES-CTR-HMAC round-trip: PASS');
    console.log('scrypt key wrapping: PASS');
    console.log('Audit events:', audit.length);
}

async function main() {
    runTests();

    const keyManager = new KeyManager();
    keyManager.on('keyRotated', event => {
        console.log(
            `Key rotation event: ${event.keyId}`
        );
    });

    const metadata = keyManager.generateKey();
    const key = keyManager.getActiveKey();

    const payload = Buffer.from(JSON.stringify({
        service: 'repository-governance',
        branch: 'main',
        classification: 'confidential',
        generatedAt: new Date().toISOString()
    }));

    const envelope = aesGcmEncrypt(
        key,
        payload,
        Buffer.from(`key-id=${metadata.keyId}`)
    );

    console.log('\nEnvelope metadata:');
    console.log({
        algorithm: envelope.algorithm,
        keyId: metadata.keyId,
        iv: envelope.iv.toString('base64'),
        ciphertextBytes: envelope.ciphertext.length,
        tag: envelope.tag.toString('base64')
    });

    console.log('\nDecrypted payload:');
    console.log(
        aesGcmDecrypt(key, envelope).toString()
    );
}

main().catch(error => {
    console.error(error);
    process.exitCode = 1;
});
