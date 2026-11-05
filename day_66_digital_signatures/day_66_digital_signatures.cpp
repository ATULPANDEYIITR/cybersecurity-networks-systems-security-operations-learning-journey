#include <algorithm>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <numeric>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * Digital Signature Mechanics and Trust Evaluation.
 *
 * This program uses a deliberately small RSA implementation to
 * demonstrate modular signing and verification.
 *
 * SECURITY WARNING:
 * The small integer key sizes are cryptographically insecure.
 * This is an educational mathematical simulation, not a production
 * cryptographic implementation.
 *
 * Production systems must use established cryptographic libraries,
 * secure RSA/ECDSA/Ed25519 implementations, and validated certificates.
 */

using namespace std;

using Integer = uint64_t;

Integer gcdValue(Integer a, Integer b) {
    while (b != 0) {
        Integer temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Multiplication without unsigned integer overflow.
Integer multiplyMod(Integer a, Integer b, Integer mod) {
    Integer result = 0;
    a %= mod;

    while (b > 0) {
        if (b & 1) {
            result = (result + a) % mod;
        }

        a = (a + a) % mod;
        b >>= 1;
    }

    return result;
}

Integer powerMod(Integer base, Integer exponent, Integer mod) {
    if (mod == 0) {
        throw invalid_argument("Modulus cannot be zero");
    }

    Integer result = 1;
    base %= mod;

    while (exponent > 0) {
        if (exponent & 1) {
            result = multiplyMod(result, base, mod);
        }

        base = multiplyMod(base, base, mod);
        exponent >>= 1;
    }

    return result;
}

Integer modularInverse(Integer a, Integer modulus) {
    if (modulus > static_cast<Integer>(
            numeric_limits<int64_t>::max())) {
        throw overflow_error("Modulus exceeds supported range");
    }

    int64_t t = 0;
    int64_t newT = 1;
    int64_t r = static_cast<int64_t>(modulus);
    int64_t newR = static_cast<int64_t>(a);

    while (newR != 0) {
        int64_t quotient = r / newR;

        int64_t tempT = t - quotient * newT;
        t = newT;
        newT = tempT;

        int64_t tempR = r - quotient * newR;
        r = newR;
        newR = tempR;
    }

    if (r != 1) {
        throw invalid_argument("Modular inverse does not exist");
    }

    if (t < 0) {
        t += static_cast<int64_t>(modulus);
    }

    return static_cast<Integer>(t);
}

// Educational RSA key model.
struct RSAKey {
    Integer modulus;
    Integer exponent;
};

struct RSAKeyPair {
    RSAKey publicKey;
    RSAKey privateKey;
};

RSAKeyPair generateEducationalRSAKey(
    Integer p,
    Integer q,
    Integer publicExponent = 65537
) {
    if (p < 3 || q < 3 || p == q) {
        throw invalid_argument("Invalid RSA prime candidates");
    }

    Integer phi = (p - 1) * (q - 1);
    Integer modulus = p * q;

    if (gcdValue(publicExponent, phi) != 1) {
        throw invalid_argument(
            "Public exponent is not coprime with phi"
        );
    }

    Integer privateExponent = modularInverse(
        publicExponent, phi
    );

    return {
        {modulus, publicExponent},
        {modulus, privateExponent}
    };
}

enum class CertificateStatus {
    VALID,
    EXPIRED,
    REVOKED,
    UNTRUSTED,
    INVALID
};

string toString(CertificateStatus status) {
    switch (status) {
        case CertificateStatus::VALID:
            return "VALID";
        case CertificateStatus::EXPIRED:
            return "EXPIRED";
        case CertificateStatus::REVOKED:
            return "REVOKED";
        case CertificateStatus::UNTRUSTED:
            return "UNTRUSTED";
        case CertificateStatus::INVALID:
            return "INVALID";
    }

    return "UNKNOWN";
}

struct Certificate {
    string subject;
    string issuer;
    string serial;
    RSAKey subjectPublicKey;
    Integer notBefore;
    Integer notAfter;
    Integer certificateSignature;
};

struct SignedDocument {
    string documentId;
    string content;
    string signer;
    Integer signature;
    string certificateSerial;
};

class CertificateAuthority {
private:
    string name;
    RSAKeyPair keys;
    set<string> revokedSerials;

    static Integer certificateMessage(const Certificate& cert) {
        // Small integer encoding for educational simulation only.
        Integer value = 0;

        for (unsigned char ch : cert.subject + "|" + cert.issuer
                + "|" + cert.serial) {
            value = (value * 131 + ch) % cert.subjectPublicKey.modulus;
        }

        value = (value * 131 + cert.subjectPublicKey.modulus)
                % keysafeModulus(cert);

        return value;
    }

    static Integer keysafeModulus(const Certificate& cert) {
        return cert.subjectPublicKey.modulus;
    }

public:
    CertificateAuthority(string caName, RSAKeyPair keyPair)
        : name(std::move(caName)), keys(keyPair) {}

    const string& getName() const {
        return name;
    }

    const RSAKey& getPublicKey() const {
        return keys.publicKey;
    }

    Certificate issue(
        const string& subject,
        const RSAKey& publicKey,
        const string& serial,
        Integer notBefore,
        Integer notAfter
    ) const {
        if (subject.empty() || serial.empty()) {
            throw invalid_argument("Subject and serial are required");
        }

        if (notAfter <= notBefore) {
            throw invalid_argument("Invalid validity interval");
        }

        if (publicKey.modulus != keys.publicKey.modulus) {
            throw invalid_argument(
                "Educational CA requires compatible modulus"
            );
        }

        Certificate cert{
            subject,
            name,
            serial,
            publicKey,
            notBefore,
            notAfter,
            0
        };

        cert.certificateSignature = powerMod(
            certificateMessage(cert),
            keys.privateKey.exponent,
            keys.privateKey.modulus
        );

        return cert;
    }

    void revoke(const string& serial) {
        revokedSerials.insert(serial);
    }

    bool isRevoked(const string& serial) const {
        return revokedSerials.count(serial) > 0;
    }

    bool verifyCertificate(const Certificate& cert) const {
        if (cert.issuer != name) {
            return false;
        }

        Integer recovered = powerMod(
            cert.certificateSignature,
            keys.publicKey.exponent,
            keys.publicKey.modulus
        );

        return recovered == certificateMessage(cert);
    }
};

class DigitalSigner {
private:
    string identity;
    RSAKeyPair keys;

    static Integer messageValue(const string& content, Integer modulus) {
        // Educational integer encoding, not a secure hash function.
        Integer value = 0;

        for (unsigned char ch : content) {
            value = (value * 257 + ch) % modulus;
        }

        return value;
    }

public:
    DigitalSigner(string name, RSAKeyPair keyPair)
        : identity(std::move(name)), keys(keyPair) {
        if (identity.empty()) {
            throw invalid_argument("Identity cannot be empty");
        }
    }

    const string& getIdentity() const {
        return identity;
    }

    const RSAKey& getPublicKey() const {
        return keys.publicKey;
    }

    Integer sign(const string& message) const {
        if (message.empty()) {
            throw invalid_argument("Cannot sign empty content");
        }

        return powerMod(
            messageValue(message, keys.privateKey.modulus),
            keys.privateKey.exponent,
            keys.privateKey.modulus
        );
    }

    bool verify(
        const string& message,
        Integer signature,
        const RSAKey& publicKey
    ) const {
        if (message.empty()) {
            return false;
        }

        Integer recovered = powerMod(
            signature,
            publicKey.exponent,
            publicKey.modulus
        );

        return recovered == messageValue(
            message, publicKey.modulus
        );
    }
};

class TrustStore {
private:
    map<string, RSAKey> trustedAuthorities;

public:
    void addTrustAnchor(const string& name, const RSAKey& key) {
        if (name.empty()) {
            throw invalid_argument("Trust anchor name is required");
        }

        trustedAuthorities[name] = key;
    }

    bool trusts(const string& issuer) const {
        return trustedAuthorities.count(issuer) > 0;
    }
};

class VerificationEngine {
private:
    const TrustStore& trustStore;
    const CertificateAuthority& authority;

public:
    VerificationEngine(
        const TrustStore& store,
        const CertificateAuthority& ca
    ) : trustStore(store), authority(ca) {}

    CertificateStatus evaluate(
        const SignedDocument& document,
        const Certificate& certificate,
        const DigitalSigner& signer,
        Integer currentTime
    ) const {
        if (document.certificateSerial != certificate.serial) {
            return CertificateStatus::INVALID;
        }

        if (authority.isRevoked(certificate.serial)) {
            return CertificateStatus::REVOKED;
        }

        if (
            currentTime < certificate.notBefore ||
            currentTime > certificate.notAfter
        ) {
            return CertificateStatus::EXPIRED;
        }

        if (!trustStore.trusts(certificate.issuer)) {
            return CertificateStatus::UNTRUSTED;
        }

        if (!authority.verifyCertificate(certificate)) {
            return CertificateStatus::INVALID;
        }

        if (certificate.subject != document.signer ||
            certificate.subject != signer.getIdentity()) {
            return CertificateStatus::INVALID;
        }

        if (
            certificate.subjectPublicKey.modulus !=
                signer.getPublicKey().modulus ||
            certificate.subjectPublicKey.exponent !=
                signer.getPublicKey().exponent
        ) {
            return CertificateStatus::INVALID;
        }

        bool valid = signer.verify(
            document.content,
            document.signature,
            certificate.subjectPublicKey
        );

        return valid
            ? CertificateStatus::VALID
            : CertificateStatus::INVALID;
    }
};

int main() {
    try {
        cout << "DIGITAL SIGNATURE AND TRUST ENGINE\n";
        cout << "Educational RSA simulation\n\n";

        // All keys use deliberately tiny educational parameters.
        const Integer p = 61;
        const Integer q = 53;

        RSAKeyPair caKeys = generateEducationalRSAKey(p, q);
        RSAKeyPair aliceKeys = generateEducationalRSAKey(p, q);

        CertificateAuthority ca("Enterprise Root CA", caKeys);

        TrustStore trustStore;
        trustStore.addTrustAnchor(ca.getName(), ca.getPublicKey());

        DigitalSigner alice("alice@enterprise.example", aliceKeys);

        Integer now = 1000000;

        Certificate certificate = ca.issue(
            alice.getIdentity(),
            alice.getPublicKey(),
            "CERT-1001",
            now - 100,
            now + 10000
        );

        string original =
            "Contract CT-1001: Payment INR 500000";

        SignedDocument document{
            "DOC-1001",
            original,
            alice.getIdentity(),
            alice.sign(original),
            certificate.serial
        };

        VerificationEngine engine(trustStore, ca);

        cout << "Document: " << document.documentId << '\n';
        cout << "Signer: " << document.signer << '\n';
        cout << "Certificate: " << certificate.serial << '\n';

        auto status = engine.evaluate(
            document, certificate, alice, now
        );

        cout << "Original verification: "
             << toString(status) << '\n';

        if (status != CertificateStatus::VALID) {
            throw runtime_error("Valid document failed verification");
        }

        // Content modification invalidates the original signature.
        SignedDocument tampered = document;
        tampered.content += " MODIFIED";

        cout << "Tampered document: "
             << toString(engine.evaluate(
                    tampered, certificate, alice, now
                )) << '\n';

        // Certificate expiration.
        cout << "Expired certificate: "
             << toString(engine.evaluate(
                    document,
                    certificate,
                    alice,
                    certificate.notAfter + 1
                )) << '\n';

        // Revocation.
        ca.revoke(certificate.serial);

        cout << "Revoked certificate: "
             << toString(engine.evaluate(
                    document, certificate, alice, now
                )) << '\n';

        // Mathematical edge case.
        try {
            modularInverse(6, 12);
        } catch (const invalid_argument& error) {
            cout << "Invalid inverse handled: "
                 << error.what() << '\n';
        }

        cout << "\nExecution completed.\n";

    } catch (const exception& error) {
        cerr << "Security engine error: "
             << error.what() << '\n';
        return 1;
    }

    return 0;
}
