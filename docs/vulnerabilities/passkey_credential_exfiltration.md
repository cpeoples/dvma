# Passkey Credential Exfiltration

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `passkey_credential_exfiltration` |
| Category | `auth` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-2, MASVS-STORAGE-1, MASVS-CRYPTO-2 |
| MASWE | MASWE-0003 |
| MASTG (v2 tests) | MASTG-TEST-0287, MASTG-TEST-0301, MASTG-TEST-0302 |
| MASTG demos | MASTG-DEMO-0059, MASTG-DEMO-0068 |
| CWE | CWE-522, CWE-312 |
| Suggested tools | objection, frida, r2frida |

## Description

Passkey/credential material is cached in app-private storage without hardware-backed protection, allowing extraction.

## Reproduce in the app

DVMA is the harness: open **Passkey Credential Exfiltration** (`passkey_credential_exfiltration`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- objection
- frida
- r2frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-2, MASVS-STORAGE-1, MASVS-CRYPTO-2
- OWASP MASWE: MASWE-0003
- OWASP MASTG (v2 tests): MASTG-TEST-0287, MASTG-TEST-0301, MASTG-TEST-0302
- OWASP MASTG demos: MASTG-DEMO-0059, MASTG-DEMO-0068
- CWE: CWE-522, CWE-312
