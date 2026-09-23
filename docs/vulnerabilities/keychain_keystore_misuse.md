# Keychain/Keystore Misuse

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `keychain_keystore_misuse` |
| Category | `storage` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M9 |
| MASVS | MASVS-STORAGE-1, MASVS-CRYPTO-2 |
| MASWE | MASWE-0003 |
| MASTG (v2 tests) | MASTG-TEST-0287, MASTG-TEST-0300, MASTG-TEST-0301 |
| MASTG demos | MASTG-DEMO-0059 |
| CWE | CWE-312, CWE-522 |
| Suggested tools | objection, frida, r2frida |

## Description

Secrets stored without hardware-backed protection / with weak accessibility flags.

## Reproduce in the app

DVMA is the harness: open **Keychain/Keystore Misuse** (`keychain_keystore_misuse`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- objection
- frida
- r2frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP MASVS: MASVS-STORAGE-1, MASVS-CRYPTO-2
- OWASP MASWE: MASWE-0003
- OWASP MASTG (v2 tests): MASTG-TEST-0287, MASTG-TEST-0300, MASTG-TEST-0301
- OWASP MASTG demos: MASTG-DEMO-0059
- CWE: CWE-312, CWE-522
