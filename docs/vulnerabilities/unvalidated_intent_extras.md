# Unvalidated Intent Extras

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `unvalidated_intent_extras` |
| Category | `input_validation` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-CODE-4 |
| MASWE | MASWE-0050 |
| MASTG (v2 tests) | MASTG-TEST-0375 |
| CWE | CWE-20, CWE-926 |
| Suggested tools | adb, drozer, jadx |

## Description

Intent extras trusted as-is, enabling privilege escalation.

## Reproduce in the app

DVMA is the harness: open **Unvalidated Intent Extras** (`unvalidated_intent_extras`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-CODE-4
- OWASP MASWE: MASWE-0050
- OWASP MASTG (v2 tests): MASTG-TEST-0375
- CWE: CWE-20, CWE-926
