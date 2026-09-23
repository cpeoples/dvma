# Anti-Debugging Bypass

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `anti_debugging_bypass` |
| Category | `resilience` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M7 |
| MASVS | MASVS-RESILIENCE-2 |
| MASWE | MASWE-0064 |
| MASTG (v2 tests) | MASTG-TEST-0352, MASTG-TEST-0353, MASTG-TEST-0401, MASTG-TEST-0402 |
| MASTG demos | MASTG-DEMO-0115, MASTG-DEMO-0116 |
| CWE | CWE-693 |
| Suggested tools | frida, r2frida, r2 |

## Description

Debugger check is a single function trivially patched out.

## Reproduce in the app

DVMA is the harness: open **Anti-Debugging Bypass** (`anti_debugging_bypass`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- r2frida
- r2

## Standards mapping

- OWASP Mobile Top 10 (2024): M7
- OWASP MASVS: MASVS-RESILIENCE-2
- OWASP MASWE: MASWE-0064
- OWASP MASTG (v2 tests): MASTG-TEST-0352, MASTG-TEST-0353, MASTG-TEST-0401, MASTG-TEST-0402
- OWASP MASTG demos: MASTG-DEMO-0115, MASTG-DEMO-0116
- CWE: CWE-693
