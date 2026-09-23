# Sensitive Data in Logs

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `sensitive_data_in_logs` |
| Category | `storage` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M9 |
| MASVS | MASVS-STORAGE-2 |
| MASWE | MASWE-0005 |
| MASTG (v2 tests) | MASTG-TEST-0203, MASTG-TEST-0231, MASTG-TEST-0296, MASTG-TEST-0297 |
| MASTG demos | MASTG-DEMO-0006, MASTG-DEMO-0065 |
| CWE | CWE-532 |
| Suggested tools |  |

## Description

PII, tokens, and passwords printed to system logs.

## Reproduce in the app

DVMA is the harness: open **Sensitive Data in Logs** (`sensitive_data_in_logs`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP MASVS: MASVS-STORAGE-2
- OWASP MASWE: MASWE-0005
- OWASP MASTG (v2 tests): MASTG-TEST-0203, MASTG-TEST-0231, MASTG-TEST-0296, MASTG-TEST-0297
- OWASP MASTG demos: MASTG-DEMO-0006, MASTG-DEMO-0065
- CWE: CWE-532
