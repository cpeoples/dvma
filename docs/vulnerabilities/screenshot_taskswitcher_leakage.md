# Screenshot / Task-Switcher Leakage

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `screenshot_taskswitcher_leakage` |
| Category | `storage` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M9 |
| MASVS | MASVS-STORAGE-2, MASVS-PLATFORM-3 |
| MASWE | MASWE-0038 |
| MASTG (v2 tests) | MASTG-TEST-0289, MASTG-TEST-0291, MASTG-TEST-0292, MASTG-TEST-0290 |
| MASTG demos | MASTG-DEMO-0061, MASTG-DEMO-0062 |
| CWE | CWE-200 |
| Suggested tools |  |

## Description

Sensitive screen rendered into the app-switcher snapshot with no FLAG_SECURE.

## Reproduce in the app

DVMA is the harness: open **Screenshot / Task-Switcher Leakage** (`screenshot_taskswitcher_leakage`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP MASVS: MASVS-STORAGE-2, MASVS-PLATFORM-3
- OWASP MASWE: MASWE-0038
- OWASP MASTG (v2 tests): MASTG-TEST-0289, MASTG-TEST-0291, MASTG-TEST-0292, MASTG-TEST-0290
- OWASP MASTG demos: MASTG-DEMO-0061, MASTG-DEMO-0062
- CWE: CWE-200
