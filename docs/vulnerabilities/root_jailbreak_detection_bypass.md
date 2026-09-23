# Root/Jailbreak Detection Bypass

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `root_jailbreak_detection_bypass` |
| Category | `resilience` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M7 |
| MASVS | MASVS-RESILIENCE-1 |
| MASWE | MASWE-0051 |
| MASTG (v2 tests) | MASTG-TEST-0324, MASTG-TEST-0325, MASTG-TEST-0240, MASTG-TEST-0241 |
| MASTG demos | MASTG-DEMO-0087, MASTG-DEMO-0088, MASTG-DEMO-0021 |
| CWE | CWE-693 |
| Suggested tools | frida, objection, r2frida |

## Description

Detection result gates on a client-side boolean easily hooked to false.

## Reproduce in the app

DVMA is the harness: open **Root/Jailbreak Detection Bypass** (`root_jailbreak_detection_bypass`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- objection
- r2frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M7
- OWASP MASVS: MASVS-RESILIENCE-1
- OWASP MASWE: MASWE-0051
- OWASP MASTG (v2 tests): MASTG-TEST-0324, MASTG-TEST-0325, MASTG-TEST-0240, MASTG-TEST-0241
- OWASP MASTG demos: MASTG-DEMO-0087, MASTG-DEMO-0088, MASTG-DEMO-0021
- CWE: CWE-693
