# Keychain Access-Group Authorization Confusion

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `keychain_access_group_authorization_confusion` |
| Category | `storage` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M9 |
| MASVS | MASVS-STORAGE-1, MASVS-AUTH-1 |
| MASWE | MASWE-0001 |
| MASTG (v2 tests) | MASTG-TEST-0388 |
| CWE | CWE-522, CWE-284, CWE-668 |
| Suggested tools | objection, frida, r2frida, keychain-dumper, codesign |

## Description

Over-broad kSecAttrAccessGroup / a shared access group / synchronizable or wrongly-scoped accessibility flags let another app, extension, or user read Keychain items that should be isolated to this app, so items leak across the intended authorization boundary (iOS Keychain access-authorization CVE-2026-28864 class).

## Reproduce in the app

DVMA is the harness: open **Keychain Access-Group Authorization Confusion** (`keychain_access_group_authorization_confusion`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- objection
- frida
- r2frida
- keychain-dumper
- codesign

## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP MASVS: MASVS-STORAGE-1, MASVS-AUTH-1
- OWASP MASWE: MASWE-0001
- OWASP MASTG (v2 tests): MASTG-TEST-0388
- CWE: CWE-522, CWE-284, CWE-668
