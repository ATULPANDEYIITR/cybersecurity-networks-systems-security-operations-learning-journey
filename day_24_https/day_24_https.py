"""
HTTPS and TLS: From Fundamentals to Advanced Concepts
======================================================

This standalone study script teaches:

1. HTTP versus HTTPS
2. TLS terminology and architecture
3. Symmetric and asymmetric cryptography
4. Hashing and digital signatures
5. X.509 certificates
6. Certificate chains and trust anchors
7. TLS 1.2 and TLS 1.3 handshake concepts
8. Key exchange and forward secrecy
9. TLS record protection
10. Certificate inspection with OpenSSL
11. Wireshark-oriented packet analysis
12. Certificate validation and hostname verification
13. Common TLS failures
14. Security considerations
15. Performance and production considerations

The cryptographic demonstrations use Python's standard library where
possible. They are educational models, not replacements for production
cryptographic libraries or operating-system TLS implementations.

OpenSSL and Wireshark are discussed through executable command examples
and packet-analysis concepts. They do not need to be installed to run
this Python file.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional


# ============================================================================
# SECTION 1: BASIC UTILITIES
# ============================================================================

def title(text: str) -> None:
    """Print a readable section heading."""
    print("\n" + "=" * 78)
    print(text)
    print("=" * 78)


def subsection(text: str) -> None:
    print("\n" + "-" * 78)
    print(text)
    print("-" * 78)


def explain(label: str, value: object) -> None:
    print(f"{label}: {value}")


# ============================================================================
# SECTION 2: HTTP VERSUS HTTPS
# ============================================================================

def demonstrate_http_vs_https() -> None:
    title("1. HTTP versus HTTPS")

    http_request = (
        "GET /login HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "\r\n"
        "username=alice&password=example"
    )

    print("A simplified HTTP request is ordinary application data:")
    print(http_request)

    print("\nHTTPS does not replace HTTP.")
    print("HTTPS means HTTP transported through a protected TLS connection.")
    print("The conceptual stack is:")
    print("Application: HTTP")
    print("Security:    TLS")
    print("Transport:   TCP")
    print("Network:     IP")

    print("\nTLS primarily provides:")
    print("  Confidentiality - outsiders should not read protected application data.")
    print("  Integrity       - modifications should be detected.")
    print("  Authentication  - certificates can authenticate the server.")
    print("  Key establishment - endpoints establish fresh traffic keys.")


# ============================================================================
# SECTION 3: HASHING
# ============================================================================

def demonstrate_hashing() -> None:
    title("2. Cryptographic hashing")

    message = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

    sha256_digest = hashlib.sha256(message).hexdigest()
    sha512_digest = hashlib.sha512(message).hexdigest()

    explain("Message", message.decode())
    explain("SHA-256", sha256_digest)
    explain("SHA-512", sha512_digest)

    modified = message.replace(b"/ HTTP", b"/index.html HTTP")
    modified_digest = hashlib.sha256(modified).hexdigest()

    print("\nA one-byte or small message change produces a substantially different hash.")
    explain("Modified SHA-256", modified_digest)

    print("\nImportant distinction:")
    print("A cryptographic hash is not encryption.")
    print("Hashing is designed to be one-way; encryption is designed to be reversible")
    print("when the authorized recipient has the required key.")


# ============================================================================
# SECTION 4: HMAC
# ============================================================================

def demonstrate_hmac() -> None:
    title("3. Message authentication with HMAC")

    secret_key = b"demo-session-key"
    message = b"transfer=1000&account=42"

    tag = hmac.new(secret_key, message, hashlib.sha256).hexdigest()

    print("HMAC combines a secret key with a message and a cryptographic hash.")
    explain("Message", message.decode())
    explain("HMAC-SHA256", tag)

    valid = hmac.compare_digest(
        tag,
        hmac.new(secret_key, message, hashlib.sha256).hexdigest(),
    )

    tampered = message.replace(b"1000", b"9000")
    tampered_valid = hmac.compare_digest(
        tag,
        hmac.new(secret_key, tampered, hashlib.sha256).hexdigest(),
    )

    explain("Original verification", valid)
    explain("Tampered verification", tampered_valid)


# ============================================================================
# SECTION 5: TOY SYMMETRIC ENCRYPTION MODEL
# ============================================================================

def xor_demo_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Educational XOR construction.

    This is NOT secure encryption because it has none of the properties of a
    modern authenticated cipher. It is used only to make the basic idea of
    symmetric encryption visible.
    """
    return bytes(
        value ^ key[index % len(key)]
        for index, value in enumerate(plaintext)
    )


def demonstrate_symmetric_encryption() -> None:
    title("4. Symmetric encryption")

    key = b"KEY"
    plaintext = b"HTTPS protects application data."

    ciphertext = xor_demo_encrypt(key, plaintext)
    recovered = xor_demo_encrypt(key, ciphertext)

    explain("Plaintext", plaintext.decode())
    explain("Toy ciphertext", ciphertext.hex())
    explain("Recovered plaintext", recovered.decode())

    print("\nThe same secret key is used for both directions of this toy example.")
    print("Real TLS uses modern authenticated encryption such as AES-GCM or")
    print("ChaCha20-Poly1305 rather than XOR.")


# ============================================================================
# SECTION 6: ASYMMETRIC CRYPTOGRAPHY MODEL
# ============================================================================

def demonstrate_asymmetric_concept() -> None:
    title("5. Asymmetric cryptography")

    print(
        """
Asymmetric cryptography uses a key pair:

  Public key  -> intended to be distributed.
  Private key -> must remain secret.

TLS historically used RSA in several roles, but modern TLS 1.3 normally
uses ephemeral Diffie-Hellman key exchange, such as ECDHE, for establishing
shared secrets. The server's certificate normally authenticates a public
key and its corresponding identity rather than directly encrypting all
application traffic.

The important architectural separation is:

  Authentication / signatures
            +
  Key agreement
            +
  Symmetric authenticated encryption
            =
  Efficient secure channel
"""
    )


# ============================================================================
# SECTION 7: X.509 CERTIFICATE MODEL
# ============================================================================

@dataclass
class Certificate:
    subject: str
    issuer: str
    public_key_algorithm: str
    signature_algorithm: str
    dns_names: list[str]
    is_ca: bool
    not_before: str
    not_after: str
    serial_number: str = field(default_factory=lambda: secrets.token_hex(8))

    def describe(self) -> None:
        print(f"Subject:             {self.subject}")
        print(f"Issuer:              {self.issuer}")
        print(f"Public-key algorithm:{self.public_key_algorithm}")
        print(f"Signature algorithm: {self.signature_algorithm}")
        print(f"DNS names:           {', '.join(self.dns_names)}")
        print(f"CA certificate:      {self.is_ca}")
        print(f"Validity:            {self.not_before} -> {self.not_after}")
        print(f"Serial number:       {self.serial_number}")


def demonstrate_certificate_structure() -> None:
    title("6. X.509 certificate structure")

    root = Certificate(
        subject="Example Root CA",
        issuer="Example Root CA",
        public_key_algorithm="RSA-4096",
        signature_algorithm="RSA-PSS-SHA256",
        dns_names=[],
        is_ca=True,
        not_before="2026-01-01",
        not_after="2036-01-01",
    )

    intermediate = Certificate(
        subject="Example TLS Intermediate CA",
        issuer=root.subject,
        public_key_algorithm="RSA-3072",
        signature_algorithm="RSA-PSS-SHA256",
        dns_names=[],
        is_ca=True,
        not_before="2026-01-01",
        not_after="2031-01-01",
    )

    server = Certificate(
        subject="www.example.com",
        issuer=intermediate.subject,
        public_key_algorithm="ECDSA-P256",
        signature_algorithm="ECDSA-SHA256",
        dns_names=["www.example.com", "example.com"],
        is_ca=False,
        not_before="2026-09-01",
        not_after="2026-12-01",
    )

    print("Root certificate:")
    root.describe()

    print("\nIntermediate certificate:")
    intermediate.describe()

    print("\nServer certificate:")
    server.describe()

    print(
        """
A typical chain can therefore look like:

  Server certificate
        |
        v
  Intermediate CA
        |
        v
  Root CA / trust anchor

The root is normally already trusted by the operating system or browser.
A server usually sends its leaf certificate plus required intermediate
certificates. The client builds and validates a chain toward a trusted root.
"""
    )


# ============================================================================
# SECTION 8: CERTIFICATE CHAIN VALIDATION
# ============================================================================

def validate_certificate_chain(
    chain: Iterable[Certificate],
    trusted_roots: Iterable[Certificate],
    hostname: str,
) -> tuple[bool, list[str]]:
    """
    Educational structural validation.

    This does NOT perform real X.509 signature validation, revocation checks,
    CT checks, or cryptographic key validation. Production applications should
    delegate those operations to a mature TLS/X.509 implementation.
    """
    certificates = list(chain)
    roots = list(trusted_roots)
    problems: list[str] = []

    if not certificates:
        problems.append("No server certificate was supplied.")
        return False, problems

    leaf = certificates[0]

    if leaf.is_ca:
        problems.append("The leaf certificate is marked as a CA certificate.")

    if hostname not in leaf.dns_names:
        problems.append("Hostname does not match the certificate SAN names.")

    for current, issuer in zip(certificates, certificates[1:]):
        if current.issuer != issuer.subject:
            problems.append(
                f"Issuer mismatch: {current.subject} does not chain to "
                f"{issuer.subject}."
            )

        if not issuer.is_ca:
            problems.append(f"{issuer.subject} is not marked as a CA.")

    if certificates[-1].subject not in {root.subject for root in roots}:
        problems.append("The chain does not terminate at a trusted root.")

    return not problems, problems


def demonstrate_chain_validation() -> None:
    title("7. Certificate-chain validation")

    root = Certificate(
        subject="Demo Root CA",
        issuer="Demo Root CA",
        public_key_algorithm="RSA-4096",
        signature_algorithm="RSA-PSS-SHA256",
        dns_names=[],
        is_ca=True,
        not_before="2026-01-01",
        not_after="2036-01-01",
    )

    intermediate = Certificate(
        subject="Demo Intermediate CA",
        issuer="Demo Root CA",
        public_key_algorithm="RSA-3072",
        signature_algorithm="RSA-PSS-SHA256",
        dns_names=[],
        is_ca=True,
        not_before="2026-01-01",
        not_after="2031-01-01",
    )

    server = Certificate(
        subject="api.example.com",
        issuer="Demo Intermediate CA",
        public_key_algorithm="ECDSA-P256",
        signature_algorithm="ECDSA-SHA256",
        dns_names=["api.example.com"],
        is_ca=False,
        not_before="2026-09-01",
        not_after="2026-12-01",
    )

    valid, problems = validate_certificate_chain(
        [server, intermediate],
        [root],
        "api.example.com",
    )

    explain("Valid example", valid)
    explain("Problems", problems or "none")

    invalid, invalid_problems = validate_certificate_chain(
        [server, intermediate],
        [root],
        "attacker.example.com",
    )

    explain("Wrong-hostname example", invalid)
    explain("Problems", invalid_problems)


# ============================================================================
# SECTION 9: HOSTNAME VERIFICATION
# ============================================================================

def hostname_matches_certificate(hostname: str, dns_names: list[str]) -> bool:
    """
    Simplified hostname matching.

    Real TLS stacks implement RFC-defined wildcard and certificate rules.
    """
    hostname = hostname.lower().rstrip(".")

    for pattern in dns_names:
        pattern = pattern.lower().rstrip(".")

        if pattern == hostname:
            return True

        if pattern.startswith("*."):
            suffix = pattern[1:]
            if hostname.endswith(suffix) and hostname.count(".") == pattern.count("."):
                return True

    return False


def demonstrate_hostname_verification() -> None:
    title("8. Hostname verification")

    names = ["example.com", "*.api.example.com"]

    tests = [
        "example.com",
        "www.example.com",
        "service.api.example.com",
        "api.example.com",
        "evil.example.net",
    ]

    for hostname in tests:
        print(
            f"{hostname:28} -> "
            f"{hostname_matches_certificate(hostname, names)}"
        )

    print(
        """
Hostname verification is separate from simply asking whether a certificate
is signed by a trusted CA.

A certificate can be correctly signed and still be invalid for the hostname
being contacted. Modern certificates normally place DNS identities in the
Subject Alternative Name (SAN) extension.
"""
    )


# ============================================================================
# SECTION 10: TLS RANDOM VALUES AND NONCES
# ============================================================================

def demonstrate_randomness() -> None:
    title("9. Randomness, nonces, and fresh session material")

    client_random = secrets.token_bytes(32)
    server_random = secrets.token_bytes(32)

    explain("Client random", client_random.hex())
    explain("Server random", server_random.hex())

    print(
        "\nTLS needs strong randomness for keys, nonces, ephemeral key material, "
        "and other security-sensitive values."
    )

    print(
        "Do not replace cryptographic randomness with random.random() in real "
        "security-sensitive code."
    )


# ============================================================================
# SECTION 11: HKDF
# ============================================================================

def hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
    """Educational HKDF-Extract based on HMAC-SHA256."""
    return hmac.new(salt, input_key_material, hashlib.sha256).digest()


def hkdf_expand(
    pseudorandom_key: bytes,
    info: bytes,
    length: int,
) -> bytes:
    """Educational HKDF-Expand based on RFC 5869."""
    output = b""
    previous = b""

    for counter in range(1, 256):
        previous = hmac.new(
            pseudorandom_key,
            previous + info + bytes([counter]),
            hashlib.sha256,
        ).digest()
        output += previous

        if len(output) >= length:
            return output[:length]

    raise ValueError("Requested HKDF output is too large.")


def demonstrate_hkdf() -> None:
    title("10. Key derivation with HKDF")

    shared_secret = secrets.token_bytes(32)
    salt = secrets.token_bytes(32)

    pseudorandom_key = hkdf_extract(salt, shared_secret)
    client_key = hkdf_expand(
        pseudorandom_key,
        b"tls client application traffic key",
        32,
    )
    server_key = hkdf_expand(
        pseudorandom_key,
        b"tls server application traffic key",
        32,
    )

    explain("Shared secret", shared_secret.hex())
    explain("Client traffic key", client_key.hex())
    explain("Server traffic key", server_key.hex())

    print(
        "\nA key schedule derives multiple independent secrets from earlier "
        "keying material instead of reusing one key everywhere."
    )


# ============================================================================
# SECTION 12: TLS 1.3 HANDSHAKE MODEL
# ============================================================================

@dataclass
class HandshakeMessage:
    message_type: str
    direction: str
    purpose: str


def tls13_handshake_messages() -> list[HandshakeMessage]:
    return [
        HandshakeMessage(
            "ClientHello",
            "Client -> Server",
            "Offers protocol versions, cipher suites, extensions and key shares.",
        ),
        HandshakeMessage(
            "ServerHello",
            "Server -> Client",
            "Selects parameters and provides the server key share.",
        ),
        HandshakeMessage(
            "EncryptedExtensions",
            "Server -> Client",
            "Provides encrypted negotiated extensions.",
        ),
        HandshakeMessage(
            "Certificate",
            "Server -> Client",
            "Presents the server certificate chain.",
        ),
        HandshakeMessage(
            "CertificateVerify",
            "Server -> Client",
            "Proves possession of the private key associated with the certificate.",
        ),
        HandshakeMessage(
            "Finished",
            "Server -> Client",
            "Authenticates the handshake transcript.",
        ),
        HandshakeMessage(
            "Finished",
            "Client -> Server",
            "Client authenticates the handshake transcript.",
        ),
    ]


def demonstrate_tls13_handshake() -> None:
    title("11. TLS 1.3 handshake")

    for message in tls13_handshake_messages():
        print(f"{message.direction:18} {message.message_type:20} {message.purpose}")

    print(
        """
A simplified TLS 1.3 flow is:

Client                                        Server
  |                                              |
  | -------- ClientHello + key share ---------> |
  |                                              |
  | <------- ServerHello + key share ---------- |
  | <------ encrypted handshake messages ------ |
  |                                              |
  | -------- encrypted Finished --------------> |
  |                                              |
  | <========== protected application =========> |

The exact wire representation contains TLS records, extensions, transcript
hashes and cryptographic state not shown in this simplified diagram.
"""
    )


# ============================================================================
# SECTION 13: TLS 1.2 VERSUS TLS 1.3
# ============================================================================

def compare_tls_versions() -> None:
    title("12. TLS 1.2 versus TLS 1.3")

    comparison = [
        ("Handshake design", "More legacy options", "More constrained design"),
        ("Forward secrecy", "Depends on selected cipher suite", "Ephemeral key exchange is standard"),
        ("Cipher suites", "Authentication/key exchange can be encoded together", "Cipher suite primarily identifies AEAD/hash choices"),
        ("Round trips", "Can require more", "Designed to reduce handshake latency"),
        ("Legacy algorithms", "Broader historical support", "Removed many legacy choices"),
        ("Encrypted handshake", "Less extensive", "More handshake data becomes encrypted"),
    ]

    print(f"{'Aspect':25} {'TLS 1.2':32} {'TLS 1.3':35}")
    print("-" * 94)

    for aspect, tls12, tls13 in comparison:
        print(f"{aspect:25} {tls12:32} {tls13:35}")

    print(
        "\nTLS 1.3 does not simply mean 'stronger encryption'. Its redesign also "
        "reduces protocol complexity and removes many obsolete negotiation choices."
    )


# ============================================================================
# SECTION 14: FORWARD SECRECY
# ============================================================================

def demonstrate_forward_secrecy_concept() -> None:
    title("13. Forward secrecy")

    print(
        """
With ephemeral Diffie-Hellman key exchange, the parties create temporary
key-exchange secrets for a connection.

Conceptually:

    Client ephemeral private key
                 +
    Server ephemeral private key
                 |
                 v
       shared ephemeral secret
                 |
                 v
          TLS key schedule
                 |
                 v
       traffic encryption keys

If a long-term authentication private key is compromised later, that does
not automatically reveal old session traffic protected using independent
ephemeral secrets.

This property is called forward secrecy.

Forward secrecy is a protocol property, not simply a property of the
certificate's public-key algorithm.
"""
    )


# ============================================================================
# SECTION 15: TLS RECORD LAYER
# ============================================================================

TLS_CONTENT_TYPES = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "Application Data",
}


def parse_tls_record_header(header: bytes) -> dict[str, object]:
    if len(header) != 5:
        raise ValueError("A TLS record header must contain exactly 5 bytes.")

    content_type, major, minor, length = struct.unpack("!BBBH", header)

    return {
        "content_type": TLS_CONTENT_TYPES.get(content_type, "Unknown"),
        "content_type_code": content_type,
        "legacy_record_version": f"{major}.{minor}",
        "length": length,
    }


def demonstrate_tls_record_structure() -> None:
    title("14. TLS record layer")

    example_header = bytes([22, 3, 3]) + struct.pack("!H", 120)

    parsed = parse_tls_record_header(example_header)

    for key, value in parsed.items():
        print(f"{key:25}: {value}")

    print(
        """
A TLS record contains a small header followed by a payload.

The conceptual structure is:

  Content type
  Legacy record version field
  Length
  Protected or unprotected payload, depending on protocol state

After encryption, packet captures can generally reveal metadata such as
record sizes and timing, but not the protected application plaintext when
TLS is correctly implemented and the keys are unavailable.
"""
    )


# ============================================================================
# SECTION 16: TLS ALERTS
# ============================================================================

TLS_ALERTS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    40: "handshake_failure",
    42: "bad_certificate",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    70: "protocol_version",
    80: "user_canceled",
    90: "user_canceled",
}


def demonstrate_tls_alerts() -> None:
    title("15. TLS alerts")

    for code in sorted(set(TLS_ALERTS)):
        print(f"{code:3} -> {TLS_ALERTS[code]}")

    print(
        "\nA TLS failure is often the result of incompatible protocol versions, "
        "certificate validation, authentication, or cryptographic negotiation."
    )


# ============================================================================
# SECTION 17: OPENSSL COMMANDS
# ============================================================================

def openssl_command_reference() -> None:
    title("16. OpenSSL practical commands")

    commands = {
        "Inspect a local certificate":
            "openssl x509 -in certificate.pem -text -noout",
        "Inspect certificate dates":
            "openssl x509 -in certificate.pem -noout -dates",
        "Inspect certificate SAN":
            "openssl x509 -in certificate.pem -noout -ext subjectAltName",
        "Calculate certificate fingerprint":
            "openssl x509 -in certificate.pem -noout -fingerprint -sha256",
        "Inspect a remote TLS server":
            "openssl s_client -connect example.com:443 -servername example.com",
        "Force TLS 1.3":
            "openssl s_client -connect example.com:443 -servername example.com -tls1_3",
        "Show certificate chain":
            "openssl s_client -connect example.com:443 -servername example.com -showcerts",
    }

    for description, command in commands.items():
        print(f"\n{description}:")
        print(f"  {command}")

    print(
        """
OpenSSL s_client is especially useful for learning because it exposes the
certificate chain and negotiated TLS parameters without requiring a custom
program.

Do not disable certificate verification in production merely to make a
connection succeed.
"""
    )


def try_local_openssl_version() -> None:
    title("17. Optional OpenSSL environment check")

    try:
        result = subprocess.run(
            ["openssl", "version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

        if result.returncode == 0:
            print("OpenSSL detected:")
            print(result.stdout.strip())
        else:
            print("OpenSSL was found but returned an error.")
            print(result.stderr.strip())
    except (FileNotFoundError, subprocess.SubprocessError) as error:
        print("OpenSSL is not available in PATH.")
        print(f"Reason: {error}")


# ============================================================================
# SECTION 18: WIRESHARK FILTERS
# ============================================================================

def wireshark_filter_reference() -> None:
    title("18. Wireshark analysis")

    filters = {
        "TLS traffic":
            "tls",
        "TCP port 443":
            "tcp.port == 443",
        "TLS handshake messages":
            "tls.handshake",
        "ClientHello":
            "tls.handshake.type == 1",
        "ServerHello":
            "tls.handshake.type == 2",
        "Certificate":
            "tls.handshake.type == 11",
        "TLS alerts":
            "tls.alert_message",
        "TCP retransmissions":
            "tcp.analysis.retransmission",
    }

    for description, expression in filters.items():
        print(f"{description:32} {expression}")

    print(
        """
A packet-analysis workflow can be:

1. Capture only traffic generated by the test application.
2. Identify the TCP connection to port 443.
3. Follow the TCP stream.
4. Inspect ClientHello and ServerHello.
5. Inspect certificate messages when visible.
6. Identify negotiated TLS version and extensions.
7. Observe encrypted application-data records.
8. Compare packet timing, sizes and retransmissions.
9. Use session keys only in controlled environments when decryption is
   intentionally configured.

TLS protects content, but metadata such as destination IP, packet sizes and
timing can remain observable.
"""
    )


# ============================================================================
# SECTION 19: REAL TLS CONNECTION USING PYTHON'S STANDARD LIBRARY
# ============================================================================

def demonstrate_real_tls_socket(
    hostname: str = "example.com",
    port: int = 443,
    timeout: float = 5.0,
) -> None:
    title("19. Real TLS connection using Python ssl")

    print(
        f"Attempting a normal certificate-validated TLS connection to "
        f"{hostname}:{port}."
    )

    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as tls_socket:
                print("TLS connection established.")
                print(f"TLS version: {tls_socket.version()}")
                print(f"Cipher:      {tls_socket.cipher()}")
                print(f"Peer:        {tls_socket.getpeercert().get('subject')}")
    except (OSError, ssl.SSLError) as error:
        print("The network demonstration could not be completed.")
        print(f"Reason: {error}")
        print(
            "This does not affect the offline educational demonstrations in "
            "the remainder of the script."
        )


# ============================================================================
# SECTION 20: HTTPS REQUEST USING STANDARD LIBRARY
# ============================================================================

def demonstrate_https_request(
    hostname: str = "example.com",
    path: str = "/",
) -> None:
    title("20. HTTPS request structure")

    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        "User-Agent: TLS-Study-Client/1.0\r\n"
        "Connection: close\r\n"
        "\r\n"
    )

    print("The HTTP message is created at the application layer:")
    print(request)

    print(
        "TLS then protects the bytes while transporting them between the "
        "client and server."
    )


# ============================================================================
# SECTION 21: CERTIFICATE-PINNING DISCUSSION
# ============================================================================

def demonstrate_pinning_tradeoffs() -> None:
    title("21. Certificate pinning")

    print(
        """
Traditional validation:

    Server certificate
          |
          v
    Trusted CA chain
          |
          v
    Hostname verification
          |
          v
    Valid TLS identity

Pinning adds an application-specific expectation about a certificate or
public key.

Potential benefit:
  - Can restrict accepted keys beyond the normal CA trust model.

Operational risks:
  - Incorrect pin deployment can make legitimate server rotation fail.
  - Recovery from a lost or compromised key can become difficult.
  - Modern platform guidance generally favors carefully designed trust
    mechanisms rather than blindly implementing static pins.

The correct choice depends on the threat model and operational environment.
"""
    )


# ============================================================================
# SECTION 22: COMMON TLS FAILURE SIMULATIONS
# ============================================================================

@dataclass
class TLSFailure:
    symptom: str
    likely_causes: list[str]
    diagnostic_action: str


def demonstrate_failure_modes() -> None:
    title("22. Common TLS failures")

    failures = [
        TLSFailure(
            "unknown_ca",
            [
                "Missing intermediate certificate",
                "Untrusted root",
                "Private enterprise CA not installed",
            ],
            "Inspect the chain with OpenSSL and compare it with the client's trust store.",
        ),
        TLSFailure(
            "hostname mismatch",
            [
                "Wrong certificate deployed",
                "Requested hostname absent from SAN",
            ],
            "Inspect subjectAltName and compare it with the actual hostname.",
        ),
        TLSFailure(
            "expired certificate",
            [
                "Certificate validity period ended",
                "Incorrect system clock",
            ],
            "Inspect certificate validity dates and system time.",
        ),
        TLSFailure(
            "handshake_failure",
            [
                "Incompatible protocol versions",
                "No mutually supported parameters",
                "Server-side policy rejection",
            ],
            "Inspect ClientHello and ServerHello and compare TLS policies.",
        ),
        TLSFailure(
            "bad_record_mac",
            [
                "Corrupted or altered protected data",
                "Protocol/state synchronization problem",
            ],
            "Inspect packet loss, retransmission and TLS implementation errors.",
        ),
    ]

    for failure in failures:
        print(f"\nSymptom: {failure.symptom}")
        print("Possible causes:")
        for cause in failure.likely_causes:
            print(f"  - {cause}")
        print(f"Diagnostic action: {failure.diagnostic_action}")


# ============================================================================
# SECTION 23: SECURITY CHECKLIST
# ============================================================================

def security_checklist() -> None:
    title("23. TLS security checklist")

    checklist = [
        "Use a maintained TLS implementation.",
        "Prefer TLS 1.3 where compatibility permits.",
        "Keep certificate chains valid and correctly ordered.",
        "Verify hostnames.",
        "Protect private keys with appropriate operational controls.",
        "Use strong cryptographic randomness.",
        "Avoid obsolete protocols and algorithms.",
        "Do not disable certificate verification to bypass errors.",
        "Monitor certificate expiration.",
        "Protect private key backups.",
        "Use secure session-ticket and key-management policies.",
        "Log TLS failures without exposing secrets.",
        "Avoid placing passwords or tokens in diagnostic logs.",
        "Patch the TLS library and operating system.",
        "Test certificate renewal before production expiry.",
    ]

    for item in checklist:
        print(f"[ ] {item}")


# ============================================================================
# SECTION 24: PERFORMANCE CONSIDERATIONS
# ============================================================================

def performance_considerations() -> None:
    title("24. TLS performance considerations")

    considerations = [
        ("Handshake cost", "Cryptographic operations and network round trips add latency."),
        ("Connection reuse", "HTTP keep-alive and connection pooling reduce repeated handshakes."),
        ("HTTP/2", "Multiplexing can reduce the number of connections required."),
        ("HTTP/3", "Uses QUIC instead of TCP and integrates TLS 1.3 into QUIC."),
        ("Session resumption", "Can reduce the cost of reconnecting to a known server."),
        ("Certificate chains", "Larger chains increase handshake bytes."),
        ("CPU", "Modern AEAD algorithms are designed for efficient bulk protection."),
    ]

    for subject, explanation in considerations:
        print(f"{subject:20}: {explanation}")


# ============================================================================
# SECTION 25: ADVANCED CONCEPTS
# ============================================================================

def advanced_concepts() -> None:
    title("25. Advanced TLS concepts")

    concepts = {
        "SNI":
            "Server Name Indication lets a client indicate the intended hostname during TLS setup.",
        "ALPN":
            "Application-Layer Protocol Negotiation selects protocols such as HTTP/1.1 or HTTP/2.",
        "OCSP":
            "Online Certificate Status Protocol can provide certificate revocation status.",
        "CRL":
            "Certificate Revocation Lists contain certificates that a CA has revoked.",
        "Certificate Transparency":
            "Publicly auditable logs help detect improperly issued publicly trusted certificates.",
        "0-RTT":
            "TLS 1.3 early data can reduce latency but requires replay-aware application design.",
        "Session resumption":
            "Previously established TLS state can reduce the cost of a later connection.",
        "ECH":
            "Encrypted ClientHello is designed to protect selected ClientHello information from observers.",
        "mTLS":
            "Mutual TLS authenticates both server and client with certificates.",
        "HSTS":
            "HTTP Strict Transport Security instructs compatible browsers to use HTTPS for a site.",
    }

    for concept, explanation in concepts.items():
        print(f"\n{concept}")
        print(textwrap.fill(explanation, width=76))


# ============================================================================
# SECTION 26: SIMPLE TLS STATE MACHINE
# ============================================================================

class TLSStateMachine:
    """Small educational state machine representing major TLS phases."""

    STATES = (
        "START",
        "CLIENT_HELLO_SENT",
        "SERVER_HELLO_RECEIVED",
        "CERTIFICATE_VALIDATED",
        "HANDSHAKE_KEYS_READY",
        "APPLICATION_KEYS_READY",
        "CONNECTED",
        "CLOSED",
    )

    def __init__(self) -> None:
        self.state = "START"

    def transition(self, next_state: str) -> None:
        if next_state not in self.STATES:
            raise ValueError(f"Unknown TLS state: {next_state}")

        valid_transitions = {
            "START": {"CLIENT_HELLO_SENT", "CLOSED"},
            "CLIENT_HELLO_SENT": {"SERVER_HELLO_RECEIVED", "CLOSED"},
            "SERVER_HELLO_RECEIVED": {"CERTIFICATE_VALIDATED", "CLOSED"},
            "CERTIFICATE_VALIDATED": {"HANDSHAKE_KEYS_READY", "CLOSED"},
            "HANDSHAKE_KEYS_READY": {"APPLICATION_KEYS_READY", "CLOSED"},
            "APPLICATION_KEYS_READY": {"CONNECTED", "CLOSED"},
            "CONNECTED": {"CLOSED"},
            "CLOSED": set(),
        }

        if next_state not in valid_transitions[self.state]:
            raise RuntimeError(
                f"Invalid TLS state transition: "
                f"{self.state} -> {next_state}"
            )

        self.state = next_state


def demonstrate_state_machine() -> None:
    title("26. TLS state machine")

    machine = TLSStateMachine()

    sequence = [
        "CLIENT_HELLO_SENT",
        "SERVER_HELLO_RECEIVED",
        "CERTIFICATE_VALIDATED",
        "HANDSHAKE_KEYS_READY",
        "APPLICATION_KEYS_READY",
        "CONNECTED",
        "CLOSED",
    ]

    for state in sequence:
        machine.transition(state)
        print(f"State -> {machine.state}")

    try:
        machine.transition("CONNECTED")
    except RuntimeError as error:
        print(f"Expected failure: {error}")


# ============================================================================
# SECTION 27: TRANSCRIPT HASH
# ============================================================================

def demonstrate_transcript_hash() -> None:
    title("27. Handshake transcript")

    transcript = (
        b"ClientHello"
        b"ServerHello"
        b"EncryptedExtensions"
        b"Certificate"
        b"CertificateVerify"
    )

    digest = hashlib.sha256(transcript).hexdigest()

    explain("Simplified transcript", transcript.decode())
    explain("SHA-256 transcript hash", digest)

    print(
        "\nTLS uses transcript-dependent authentication so that handshake "
        "messages cannot simply be altered without detection."
    )


# ============================================================================
# SECTION 28: THREAT MODEL
# ============================================================================

def threat_model() -> None:
    title("28. Threat model")

    threats = {
        "Passive network observer":
            "TLS confidentiality prevents ordinary packet inspection from revealing protected application plaintext.",
        "Active network attacker":
            "TLS integrity and authenticated key establishment are designed to detect unauthorized modification or impersonation.",
        "Compromised server":
            "TLS cannot protect application data after it reaches a compromised endpoint.",
        "Compromised private key":
            "Impact depends on protocol configuration, key usage, and whether past sessions had forward secrecy.",
        "Malicious or compromised CA":
            "Public-key infrastructure depends on trust anchors and certificate issuance controls.",
        "Endpoint malware":
            "TLS cannot prevent malware on an endpoint from reading plaintext before encryption or after decryption.",
    }

    for threat, protection in threats.items():
        print(f"\nThreat: {threat}")
        print(f"TLS consideration: {protection}")


# ============================================================================
# SECTION 29: MINI TEST SUITE
# ============================================================================

def run_tests() -> None:
    title("29. Built-in tests")

    key = b"abc"
    message = b"hello"

    encrypted = xor_demo_encrypt(key, message)
    assert xor_demo_encrypt(key, encrypted) == message

    tag = hmac.new(key, message, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(
        tag,
        hmac.new(key, message, hashlib.sha256).hexdigest(),
    )

    assert not hmac.compare_digest(
        tag,
        hmac.new(key, b"HELLO", hashlib.sha256).hexdigest(),
    )

    assert hostname_matches_certificate(
        "www.example.com",
        ["www.example.com"],
    )

    assert not hostname_matches_certificate(
        "evil.example.net",
        ["www.example.com"],
    )

    header = bytes([23, 3, 3]) + struct.pack("!H", 10)
    parsed = parse_tls_record_header(header)

    assert parsed["content_type"] == "Application Data"
    assert parsed["length"] == 10

    print("All local tests passed.")


# ============================================================================
# SECTION 30: STUDY MAP
# ============================================================================

def print_study_map() -> None:
    title("30. Conceptual study map")

    print(
        """
HTTPS
 |
 +-- HTTP application protocol
 |
 +-- TLS
      |
      +-- Authentication
      |     |
      |     +-- X.509 certificate
      |     +-- Certificate chain
      |     +-- Trusted root
      |     +-- Hostname verification
      |
      +-- Key establishment
      |     |
      |     +-- Ephemeral Diffie-Hellman
      |     +-- Shared secret
      |     +-- HKDF key schedule
      |
      +-- Handshake
      |     |
      |     +-- ClientHello
      |     +-- ServerHello
      |     +-- Certificate
      |     +-- CertificateVerify
      |     +-- Finished
      |
      +-- Record protection
            |
            +-- AEAD encryption
            +-- Integrity
            +-- Nonces
            +-- Application Data

Operational tools
 |
 +-- OpenSSL
 |     +-- Certificate inspection
 |     +-- TLS endpoint inspection
 |
 +-- Wireshark
       +-- Packet capture
       +-- Handshake analysis
       +-- TLS metadata
       +-- Troubleshooting
"""
    )


# ============================================================================
# MAIN PROGRAM
# ============================================================================

def main() -> None:
    print("HTTPS AND TLS COMPREHENSIVE PYTHON STUDY PROGRAM")
    print("Educational implementation and protocol exploration")
    print(f"Python version: {sys.version.split()[0]}")

    demonstrate_http_vs_https()
    demonstrate_hashing()
    demonstrate_hmac()
    demonstrate_symmetric_encryption()
    demonstrate_asymmetric_concept()
    demonstrate_certificate_structure()
    demonstrate_chain_validation()
    demonstrate_hostname_verification()
    demonstrate_randomness()
    demonstrate_hkdf()
    demonstrate_tls13_handshake()
    compare_tls_versions()
    demonstrate_forward_secrecy_concept()
    demonstrate_tls_record_structure()
    demonstrate_tls_alerts()
    openssl_command_reference()
    try_local_openssl_version()
    wireshark_filter_reference()
    demonstrate_https_request()
    demonstrate_pinning_tradeoffs()
    demonstrate_failure_modes()
    security_checklist()
    performance_considerations()
    advanced_concepts()
    demonstrate_state_machine()
    demonstrate_transcript_hash()
    threat_model()
    run_tests()
    print_study_map()

    # Network access is intentionally optional so the study program remains
    # useful in offline environments.
    if "--network" in sys.argv:
        demonstrate_real_tls_socket()

    title("Program complete")
    print(
        "The examples above separate the educational cryptographic concepts "
        "from production TLS implementation responsibilities."
    )


if __name__ == "__main__":
    main()
