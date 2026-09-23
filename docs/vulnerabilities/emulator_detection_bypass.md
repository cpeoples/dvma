# Emulator Detection Bypass

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `emulator_detection_bypass` |
| Category | `resilience` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M7 |
| MASVS | MASVS-RESILIENCE-1 |
| MASWE | MASWE-0053 |
| MASTG (v2 tests) | MASTG-TEST-0367, MASTG-TEST-0351 |
| MASTG demos | MASTG-DEMO-0131, MASTG-DEMO-0114 |
| CWE | CWE-693 |
| Suggested tools | frida, r2frida, objection |

## Description

Emulator check reads easily-spoofed build properties.

## Reproduce in the app

DVMA is the harness: open **Emulator Detection Bypass** (`emulator_detection_bypass`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- r2frida
- objection

## Standards mapping

- OWASP Mobile Top 10 (2024): M7
- OWASP MASVS: MASVS-RESILIENCE-1
- OWASP MASWE: MASWE-0053
- OWASP MASTG (v2 tests): MASTG-TEST-0367, MASTG-TEST-0351
- OWASP MASTG demos: MASTG-DEMO-0131, MASTG-DEMO-0114
- CWE: CWE-693
