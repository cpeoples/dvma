# Missing FLAG_SECURE (screen recording exposure)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `missing_flag_secure` |
| Category | `platform` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-3, MASVS-STORAGE-2 |
| MASWE | MASWE-0038 |
| MASTG (v2 tests) | MASTG-TEST-0291, MASTG-TEST-0293 |
| MASTG demos | MASTG-DEMO-0061 |
| CWE | CWE-200 |
| Suggested tools | adb shell screencap, adb shell screenrecord, scrcpy |

## Description

Sensitive screen allows screenshots/recording (no FLAG_SECURE).

## Reproduce in the app

DVMA is the harness: open **Missing FLAG_SECURE (screen recording exposure)** (`missing_flag_secure`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb shell screencap
- adb shell screenrecord
- scrcpy

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-3, MASVS-STORAGE-2
- OWASP MASWE: MASWE-0038
- OWASP MASTG (v2 tests): MASTG-TEST-0291, MASTG-TEST-0293
- OWASP MASTG demos: MASTG-DEMO-0061
- CWE: CWE-200
