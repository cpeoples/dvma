# Verbose Error Handling (leaked stack traces)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `verbose_error_handling` |
| Category | `code_quality` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M7 |
| MASVS | MASVS-CODE-2 |
| MASWE | MASWE-0061 |
| MASTG (v2 tests) | MASTG-TEST-0041, MASTG-TEST-0084 |
| CWE | CWE-209, CWE-497 |
| Suggested tools | adb logcat, jadx |

## Description

Error screens render full stack traces and internal details.

## Reproduce in the app

DVMA is the harness: open **Verbose Error Handling (leaked stack traces)** (`verbose_error_handling`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb logcat
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M7
- OWASP MASVS: MASVS-CODE-2
- OWASP MASWE: MASWE-0061
- OWASP MASTG (v2 tests): MASTG-TEST-0041, MASTG-TEST-0084
- CWE: CWE-209, CWE-497
