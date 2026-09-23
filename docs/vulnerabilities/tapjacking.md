# Tapjacking

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `tapjacking` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-3 |
| MASWE | MASWE-0039 |
| MASTG (v2 tests) | MASTG-TEST-0035, MASTG-TEST-0340 |
| MASTG demos | MASTG-DEMO-0103, MASTG-DEMO-0105 |
| CWE | CWE-1021 |
| Suggested tools | adb, jadx |

## Description

Sensitive action screen does not set filterTouchesWhenObscured.

## Reproduce in the app

DVMA is the harness: open **Tapjacking** (`tapjacking`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-3
- OWASP MASWE: MASWE-0039
- OWASP MASTG (v2 tests): MASTG-TEST-0035, MASTG-TEST-0340
- OWASP MASTG demos: MASTG-DEMO-0103, MASTG-DEMO-0105
- CWE: CWE-1021
