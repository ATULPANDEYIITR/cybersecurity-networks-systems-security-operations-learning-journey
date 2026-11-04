'use strict';

/*
 * Password Security and Account Authentication
 *
 * Node.js implementation using:
 * - crypto.scrypt
 * - Random cryptographic salts
 * - Asynchronous password derivation
 * - Versioned password records
 * - Password policy evaluation
 * - Account lockout
 * - Password rotation
 * - Event-driven security auditing
 */

const crypto = require('node:crypto');
const { promisify } = require('node:util');
const assert = require('node:assert/strict');

const scryptAsync = promisify(crypto.scrypt);

const CONFIG = Object.freeze({
    algorithm: 'scrypt',
    N: 16384,
    r: 8,
    p: 1,
    keyLength: 32,
    saltLength: 16,
    maxMemory: 64 * 1024 * 1024,
    version: 1
});


// --------------------------------------------------
// Errors
// --------------------------------------------------

class PasswordSecurityError extends Error {
    constructor(message) {
        super(message);
        this.name = 'PasswordSecurityError';
    }
}

class AccountLockedError extends PasswordSecurityError {
    constructor() {
        super('Account is temporarily locked');
        this.name = 'AccountLockedError';
    }
}


// --------------------------------------------------
// Password policy
// --------------------------------------------------

class PasswordPolicy {
    static MIN_LENGTH = 15;
    static MAX_LENGTH = 128;

    static COMMON_PASSWORDS = new Set([
        'password123456',
        'passwordpassword',
        '123456789012345',
        'qwerty123456789',
        'administrator123'
    ]);

    static evaluate(password) {
        const violations = [];

        if (typeof password !== 'string') {
            return {
                accepted: false,
                violations: ['Password must be a string']
            };
        }

        if (password.length < this.MIN_LENGTH) {
            violations.push('Password is too short');
        }

        if (password.length > this.MAX_LENGTH) {
            violations.push('Password is too long');
        }

        if (password.trim().length === 0) {
            violations.push('Password cannot be blank');
        }

        if (password.includes('\0')) {
            violations.push('Null characters are prohibited');
        }

        if (this.COMMON_PASSWORDS.has(password.toLowerCase())) {
            violations.push('Password is commonly used');
        }

        return {
            accepted: violations.length === 0,
            violations
        };
    }

    static assertValid(password) {
        const result = this.evaluate(password);

        if (!result.accepted) {
            throw new PasswordSecurityError(
                result.violations.join('; ')
            );
        }
    }
}


// --------------------------------------------------
// Password hashing service
// --------------------------------------------------

class PasswordHasher {

    constructor(config = CONFIG) {
        this.config = Object.freeze({ ...config });

        const { N, r, p, keyLength, saltLength } = this.config;

        if (
            !Number.isInteger(N) ||
            N < 2 ||
            (N & (N - 1)) !== 0 ||
            !Number.isInteger(r) ||
            r < 1 ||
            r > 16 ||
            !Number.isInteger(p) ||
            p < 1 ||
            p > 4 ||
            !Number.isInteger(keyLength) ||
            keyLength !== 32 ||
            !Number.isInteger(saltLength) ||
            saltLength < 16 ||
            saltLength > 64
        ) {
            throw new PasswordSecurityError(
                'Invalid scrypt configuration'
            );
        }
    }

    async derive(password, salt, parameters) {
        return scryptAsync(
            password,
            salt,
            parameters.keyLength,
            {
                N: parameters.N,
                r: parameters.r,
                p: parameters.p,
                maxmem: parameters.maxMemory
            }
        );
    }

    async hash(password) {
        PasswordPolicy.assertValid(password);

        const salt = crypto.randomBytes(
            this.config.saltLength
        );

        const derivedKey = await this.derive(
            password,
            salt,
            this.config
        );

        return Object.freeze({
            version: this.config.version,
            algorithm: 'scrypt',
            N: this.config.N,
            r: this.config.r,
            p: this.config.p,
            salt: salt.toString('base64'),
            hash: derivedKey.toString('base64')
        });
    }

    validateRecord(record) {
        if (
            !record ||
            record.algorithm !== 'scrypt' ||
            record.version !== 1 ||
            !Number.isInteger(record.N) ||
            record.N < 2 ||
            record.N > 262144 ||
            (record.N & (record.N - 1)) !== 0 ||
            !Number.isInteger(record.r) ||
            record.r < 1 ||
            record.r > 16 ||
            !Number.isInteger(record.p) ||
            record.p < 1 ||
            record.p > 4
        ) {
            throw new PasswordSecurityError(
                'Invalid password record'
            );
        }

        const salt = Buffer.from(record.salt, 'base64');
        const hash = Buffer.from(record.hash, 'base64');

        if (
            salt.length < 16 ||
            salt.length > 64 ||
            hash.length !== 32 ||
            salt.toString('base64') !== record.salt ||
            hash.toString('base64') !== record.hash
        ) {
            throw new PasswordSecurityError(
                'Invalid salt or hash encoding'
            );
        }

        return {
            salt,
            hash,
            parameters: {
                N: record.N,
                r: record.r,
                p: record.p,
                keyLength: hash.length,
                maxMemory: 128 * 1024 * 1024
            }
        };
    }

    async verify(password, record) {
        if (typeof password !== 'string') {
            return false;
        }

        try {
            const parsed = this.validateRecord(record);

            const candidate = await this.derive(
                password,
                parsed.salt,
                parsed.parameters
            );

            return crypto.timingSafeEqual(
                candidate,
                parsed.hash
            );
        } catch (error) {
            if (
                error instanceof PasswordSecurityError ||
                error.code === 'ERR_CRYPTO_INVALID_SCRYPT_PARAMS' ||
                error.code === 'ERR_CRYPTO_OPERATION_FAILED'
            ) {
                return false;
            }

            throw error;
        }
    }

    needsRehash(record) {
        return (
            record.algorithm !== this.config.algorithm ||
            record.N !== this.config.N ||
            record.r !== this.config.r ||
            record.p !== this.config.p
        );
    }
}


// --------------------------------------------------
// Event-driven authentication
// --------------------------------------------------

class AuthenticationService {

    constructor(hasher, options = {}) {
        this.hasher = hasher;
        this.accounts = new Map();
        this.maximumFailures = options.maximumFailures ?? 5;
        this.lockDurationMs = options.lockDurationMs ?? 60000;

        this.audit = [];
        this.listeners = new Map();
    }

    on(event, callback) {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, new Set());
        }

        this.listeners.get(event).add(callback);

        return () => {
            this.listeners.get(event)?.delete(callback);
        };
    }

    emit(event, payload) {
        const safePayload = Object.freeze({ ...payload });

        this.audit.push({
            event,
            timestamp: new Date().toISOString(),
            ...safePayload
        });

        for (const listener of this.listeners.get(event) ?? []) {
            try {
                listener(safePayload);
            } catch {
                // A failed audit subscriber must not interrupt
                // authentication processing.
            }
        }
    }

    normalizeUsername(username) {
        if (
            typeof username !== 'string' ||
            username.trim().length === 0 ||
            username.length > 100
        ) {
            throw new PasswordSecurityError(
                'Invalid username'
            );
        }

        return username.trim().toLowerCase();
    }

    async register(username, password) {
        const key = this.normalizeUsername(username);

        if (this.accounts.has(key)) {
            throw new PasswordSecurityError(
                'Account already exists'
            );
        }

        const passwordRecord = await this.hasher.hash(password);

        this.accounts.set(key, {
            username: key,
            passwordRecord,
            failedAttempts: 0,
            lockedUntil: 0,
            passwordChangedAt: Date.now()
        });

        this.emit('account.registered', {
            username: key
        });
    }

    async authenticate(username, password) {
        const key = this.normalizeUsername(username);
        const account = this.accounts.get(key);

        if (!account) {
            this.emit('authentication.failed', {
                username: key,
                reason: 'unknown_account'
            });

            return false;
        }

        if (Date.now() < account.lockedUntil) {
            throw new AccountLockedError();
        }

        if (account.lockedUntil !== 0) {
            account.lockedUntil = 0;
            account.failedAttempts = 0;
        }

        const valid = await this.hasher.verify(
            password,
            account.passwordRecord
        );

        if (!valid) {
            account.failedAttempts++;

            if (
                account.failedAttempts >= this.maximumFailures
            ) {
                account.lockedUntil =
                    Date.now() + this.lockDurationMs;

                this.emit('account.locked', {
                    username: key
                });
            }

            this.emit('authentication.failed', {
                username: key,
                reason: 'invalid_credentials'
            });

            return false;
        }

        account.failedAttempts = 0;

        if (this.hasher.needsRehash(account.passwordRecord)) {
            account.passwordRecord = await this.hasher.hash(
                password
            );

            account.passwordChangedAt = Date.now();

            this.emit('password.rehashed', {
                username: key
            });
        }

        this.emit('authentication.succeeded', {
            username: key
        });

        return true;
    }

    async changePassword(username, oldPassword, newPassword) {
        const key = this.normalizeUsername(username);
        const account = this.accounts.get(key);

        if (!account || account.lockedUntil > Date.now()) {
            throw new PasswordSecurityError(
                'Account unavailable'
            );
        }

        const valid = await this.hasher.verify(
            oldPassword,
            account.passwordRecord
        );

        if (!valid) {
            throw new PasswordSecurityError(
                'Current password is incorrect'
            );
        }

        const newRecord = await this.hasher.hash(newPassword);

        if (
            await this.hasher.verify(newPassword, account.passwordRecord)
        ) {
            throw new PasswordSecurityError(
                'New password must differ from current password'
            );
        }

        account.passwordRecord = newRecord;
        account.failedAttempts = 0;
        account.passwordChangedAt = Date.now();

        this.emit('password.changed', {
            username: key
        });
    }
}


// --------------------------------------------------
// Demonstration and automated tests
// --------------------------------------------------

async function main() {
    const hasher = new PasswordHasher();

    const service = new AuthenticationService(hasher, {
        maximumFailures: 5,
        lockDurationMs: 30000
    });

    service.on('authentication.succeeded', event => {
        console.log('Authentication succeeded:', event.username);
    });

    service.on('account.locked', event => {
        console.log('Account locked:', event.username);
    });

    const username = 'alice';
    const password = 'Correct-Horse-Battery-47!';

    await service.register(username, password);

    const account = service.accounts.get(username);

    console.log('\nPASSWORD SECURITY DEMONSTRATION');
    console.log('Algorithm:', account.passwordRecord.algorithm);
    console.log('Salt length:', Buffer.from(
        account.passwordRecord.salt, 'base64'
    ).length);
    console.log('Hash length:', Buffer.from(
        account.passwordRecord.hash, 'base64'
    ).length);

    assert.equal(
        await service.authenticate(username, password),
        true
    );

    assert.equal(
        await service.authenticate(
            username,
            'Incorrect-Password-123!'
        ),
        false
    );

    const anotherRecord = await hasher.hash(password);

    assert.notEqual(
        account.passwordRecord.salt,
        anotherRecord.salt
    );

    assert.equal(
        await hasher.verify(password, anotherRecord),
        true
    );

    assert.equal(
        await hasher.verify('WrongPassword123456!', anotherRecord),
        false
    );

    const newPassword = 'New-Enterprise-Password-84!';

    await service.changePassword(
        username,
        password,
        newPassword
    );

    assert.equal(
        await service.authenticate(username, newPassword),
        true
    );

    assert.equal(
        PasswordPolicy.evaluate('short').accepted,
        false
    );

    console.log('\nAll password security tests passed.');
    console.log('Audit events:', service.audit.length);
}

main().catch(error => {
    console.error('Execution failed:', error.message);
    process.exitCode = 1;
});
