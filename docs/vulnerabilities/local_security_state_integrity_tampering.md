# Local Security-State Integrity Tampering

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `local_security_state_integrity_tampering` |
| Category | `storage` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M9 |
| MASVS | MASVS-STORAGE-2, MASVS-AUTH-1 |
| MASWE | MASWE-0006 |
| MASTG (v2 tests) | MASTG-TEST-0338, MASTG-TEST-0387 |
| MASTG demos | MASTG-DEMO-0101, MASTG-DEMO-0150 |
| CWE | CWE-565, CWE-345, CWE-602 |
| Suggested tools | sqlite3, xxd |

## Description

A security decision (authenticated?, role, jailbreak-check result, purchase entitlement) is driven by a locally-persisted value in UserDefaults/SharedPreferences/SQLite that carries no integrity protection, so an attacker with local access flips the value and the app trusts it - no secret is stolen, the app is made to trust attacker-controlled STATE. The secure path binds security state to a keyed MAC / server authority (OWASP MASTG-BEST-0065 storage-integrity class).

## Reproduce in the app

DVMA is the harness: open **Local Security-State Integrity Tampering** (`local_security_state_integrity_tampering`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- sqlite3
- xxd

## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP MASVS: MASVS-STORAGE-2, MASVS-AUTH-1
- OWASP MASWE: MASWE-0006
- OWASP MASTG (v2 tests): MASTG-TEST-0338, MASTG-TEST-0387
- OWASP MASTG demos: MASTG-DEMO-0101, MASTG-DEMO-0150
- CWE: CWE-565, CWE-345, CWE-602
