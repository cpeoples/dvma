# Exported Android Components

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `exported_android_components` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1 |
| MASWE | MASWE-0032, MASWE-0018 |
| MASTG (v2 tests) | MASTG-TEST-0364, MASTG-TEST-0365, MASTG-TEST-0366 |
| MASTG demos | MASTG-DEMO-0128, MASTG-DEMO-0129, MASTG-DEMO-0130 |
| CWE | CWE-926, CWE-284 |
| Suggested tools | adb, drozer, apktool, jadx |

## Description

Activities/services/receivers exported with no permission checks.

## Reproduce in the app

DVMA is the harness: open **Exported Android Components** (`exported_android_components`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- apktool
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0032, MASWE-0018
- OWASP MASTG (v2 tests): MASTG-TEST-0364, MASTG-TEST-0365, MASTG-TEST-0366
- OWASP MASTG demos: MASTG-DEMO-0128, MASTG-DEMO-0129, MASTG-DEMO-0130
- CWE: CWE-926, CWE-284
