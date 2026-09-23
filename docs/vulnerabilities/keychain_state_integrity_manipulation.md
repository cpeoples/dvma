# Keychain State Integrity Manipulation

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `keychain_state_integrity_manipulation` |
| Category | `storage` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M9 |
| MASVS | MASVS-STORAGE-1, MASVS-CRYPTO-2 |
| MASWE | MASWE-0001 |
| MASTG (v2 tests) | MASTG-TEST-0387, MASTG-TEST-0338 |
| MASTG demos | MASTG-DEMO-0150, MASTG-DEMO-0101 |
| CWE | CWE-345, CWE-565, CWE-472 |
| Suggested tools | objection, frida, r2frida, keychain-dumper, plutil, xxd |

## Description

The app TRUSTS a Keychain/Keystore item as authoritative but a local attacker can MODIFY that stored state (not merely read it), so tampering with the item alters what the app authorizes or trusts - an integrity/state-manipulation failure distinct from secret confidentiality (iOS Keychain state-modification CVE-2026-28860 class).

## Reproduce in the app

DVMA is the harness: open **Keychain State Integrity Manipulation** (`keychain_state_integrity_manipulation`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- objection
- frida
- r2frida
- keychain-dumper
- plutil
- xxd

## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP MASVS: MASVS-STORAGE-1, MASVS-CRYPTO-2
- OWASP MASWE: MASWE-0001
- OWASP MASTG (v2 tests): MASTG-TEST-0387, MASTG-TEST-0338
- OWASP MASTG demos: MASTG-DEMO-0150, MASTG-DEMO-0101
- CWE: CWE-345, CWE-565, CWE-472
