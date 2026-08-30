# ============================================================
# DAY 01: CYBERSECURITY FUNDAMENTALS
# ============================================================

print("DAY 01 - CYBERSECURITY FUNDAMENTALS")


# ============================================================
# 1. WHAT IS CYBERSECURITY?
# ============================================================

print("\n1. WHAT IS CYBERSECURITY?")

print("Cybersecurity is the practice of protecting")
print("systems, networks, applications, devices, and data")
print("from unauthorized access, attacks, damage, or disruption.")


# ============================================================
# 2. WHAT NEEDS TO BE PROTECTED?
# ============================================================

print("\n2. WHAT NEEDS TO BE PROTECTED?")

assets = [
    "Data",
    "Computer Systems",
    "Networks",
    "Applications",
    "Cloud Infrastructure",
    "Devices",
    "User Accounts"
]

for asset in assets:
    print("-", asset)


# ============================================================
# 3. CIA TRIAD
# ============================================================

print("\n3. CIA TRIAD")

cia_triad = {
    "Confidentiality": "Prevent unauthorized access to information",
    "Integrity": "Prevent unauthorized modification of information",
    "Availability": "Ensure systems and information are accessible when needed"
}

for principle, meaning in cia_triad.items():
    print(principle, "->", meaning)


# ============================================================
# 4. COMMON CYBERSECURITY THREATS
# ============================================================

print("\n4. COMMON CYBERSECURITY THREATS")

threats = [
    "Phishing",
    "Malware",
    "Ransomware",
    "Password Attacks",
    "Social Engineering",
    "Denial-of-Service Attacks",
    "Data Breaches"
]

for threat in threats:
    print("-", threat)


# ============================================================
# 5. VULNERABILITY AND THREAT
# ============================================================

print("\n5. VULNERABILITY AND THREAT")

vulnerability = "Weak Password"
threat = "Password Attack"

print("Vulnerability:", vulnerability)
print("Threat:", threat)

print("\nA vulnerability is a weakness that can be exploited.")
print("A threat is a potential source of harm to a system.")


# ============================================================
# 6. RISK
# ============================================================

print("\n6. CYBERSECURITY RISK")

asset = "User Account"
vulnerability = "Weak Password"
threat = "Credential Attack"

print("Asset:", asset)
print("Vulnerability:", vulnerability)
print("Threat:", threat)

print("\nRisk occurs when a threat can exploit a vulnerability")
print("and cause harm to an asset.")


# ============================================================
# 7. AUTHENTICATION
# ============================================================

print("\n7. AUTHENTICATION")

username = "atul"
password = "secure_password"

entered_username = "atul"
entered_password = "secure_password"

if username == entered_username and password == entered_password:
    print("Authentication successful.")
else:
    print("Authentication failed.")


# ============================================================
# 8. AUTHORIZATION
# ============================================================

print("\n8. AUTHORIZATION")

user_role = "admin"

if user_role == "admin":
    print("User is authorized to access administrative features.")
else:
    print("Access denied.")


# ============================================================
# 9. AUTHENTICATION VS AUTHORIZATION
# ============================================================

print("\n9. AUTHENTICATION VS AUTHORIZATION")

print("Authentication -> Who are you?")
print("Authorization  -> What are you allowed to access?")


# ============================================================
# 10. ENCRYPTION
# ============================================================

print("\n10. ENCRYPTION")

message = "Confidential Data"

print("Original Message:", message)

print("\nEncryption transforms readable information")
print("into a protected form so unauthorized users")
print("cannot easily understand it.")


# ============================================================
# 11. PASSWORD SECURITY
# ============================================================

print("\n11. PASSWORD SECURITY")

password_requirements = [
    "Use long passwords",
    "Use unique passwords",
    "Avoid predictable information",
    "Use multi-factor authentication",
    "Do not share passwords"
]

for requirement in password_requirements:
    print("-", requirement)


# ============================================================
# 12. SECURITY CONTROLS
# ============================================================

print("\n12. SECURITY CONTROLS")

security_controls = [
    "Firewalls",
    "Access Control",
    "Encryption",
    "Multi-Factor Authentication",
    "Antivirus",
    "Backups",
    "Security Monitoring"
]

for control in security_controls:
    print("-", control)


# ============================================================
# 13. BASIC SECURITY MINDSET
# ============================================================

print("\n13. BASIC SECURITY MINDSET")

security_principles = [
    "Protect sensitive information",
    "Use least privilege",
    "Verify before trusting",
    "Keep systems updated",
    "Monitor suspicious activity",
    "Maintain backups"
]

for principle in security_principles:
    print("-", principle)


# ============================================================
# 14. BASIC CYBERSECURITY FLOW
# ============================================================

print("\n14. BASIC CYBERSECURITY FLOW")

print("""
Identify Assets
      ↓
Identify Threats
      ↓
Identify Vulnerabilities
      ↓
Assess Risk
      ↓
Apply Security Controls
      ↓
Monitor
      ↓
Respond
      ↓
Improve
""")


# ============================================================
# SUMMARY
# ============================================================

print("\n" + "=" * 60)
print("DAY 01 COMPLETED")
print("=" * 60)

print("""
Today you learned:

1. What Cybersecurity is
2. Security assets
3. CIA Triad
4. Common cybersecurity threats
5. Vulnerabilities
6. Threats
7. Risk
8. Authentication
9. Authorization
10. Encryption
11. Password security
12. Security controls
13. Basic security principles
14. Basic cybersecurity workflow
""")
