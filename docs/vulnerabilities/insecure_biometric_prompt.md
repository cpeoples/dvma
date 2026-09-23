# Insecure / Bypassable Biometric Prompt

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `insecure_biometric_prompt` |
| Category | `auth` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-2 |
| MASWE | MASWE-0020 |
| MASTG (v2 tests) | MASTG-TEST-0327, MASTG-TEST-0266, MASTG-TEST-0267, MASTG-TEST-0329 |
| MASTG demos | MASTG-DEMO-0090, MASTG-DEMO-0092 |
| CWE | CWE-287, CWE-603 |
| Suggested tools | frida, objection, r2frida, frida-trace |

## Description

Local auth is event-bound UI only; failure path is trivially bypassed.

## Reproduce in the app

DVMA is the harness: open **Insecure / Bypassable Biometric Prompt** (`insecure_biometric_prompt`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- objection
- r2frida
- frida-trace

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-2
- OWASP MASWE: MASWE-0020
- OWASP MASTG (v2 tests): MASTG-TEST-0327, MASTG-TEST-0266, MASTG-TEST-0267, MASTG-TEST-0329
- OWASP MASTG demos: MASTG-DEMO-0090, MASTG-DEMO-0092
- CWE: CWE-287, CWE-603
