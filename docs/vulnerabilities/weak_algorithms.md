# Weak Cryptographic Algorithms (MD5/SHA1/DES/RC4/ECB)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `weak_algorithms` |
| Category | `crypto` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M10 |
| MASVS | MASVS-CRYPTO-1 |
| MASWE | MASWE-0007, MASWE-0008 |
| MASTG (v2 tests) | MASTG-TEST-0210, MASTG-TEST-0221, MASTG-TEST-0232, MASTG-TEST-0317, MASTG-TEST-0211 |
| MASTG demos | MASTG-DEMO-0022, MASTG-DEMO-0023, MASTG-DEMO-0015 |
| CWE | CWE-327, CWE-328 |
| Suggested tools | frida, frida-trace, r2, MobSF |

## Description

MD5/SHA1 for password hashing and DES/RC4/AES-ECB for encryption.

## Reproduce in the app

DVMA is the harness: open **Weak Cryptographic Algorithms (MD5/SHA1/DES/RC4/ECB)** (`weak_algorithms`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- frida-trace
- r2
- MobSF

## Standards mapping

- OWASP Mobile Top 10 (2024): M10
- OWASP MASVS: MASVS-CRYPTO-1
- OWASP MASWE: MASWE-0007, MASWE-0008
- OWASP MASTG (v2 tests): MASTG-TEST-0210, MASTG-TEST-0221, MASTG-TEST-0232, MASTG-TEST-0317, MASTG-TEST-0211
- OWASP MASTG demos: MASTG-DEMO-0022, MASTG-DEMO-0023, MASTG-DEMO-0015
- CWE: CWE-327, CWE-328
