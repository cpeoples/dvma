# Anti-Tampering / Integrity Bypass

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `anti_tampering_integrity_bypass` |
| Category | `resilience` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M7 |
| MASVS | MASVS-RESILIENCE-3 |
| MASWE | MASWE-0057 |
| MASTG (v2 tests) | MASTG-TEST-0338, MASTG-TEST-0387 |
| MASTG demos | MASTG-DEMO-0101, MASTG-DEMO-0150 |
| CWE | CWE-354 |
| Suggested tools | frida, r2frida, r2 |

## Description

Integrity check never verifies anything meaningful (always passes).

## Reproduce in the app

DVMA is the harness: open **Anti-Tampering / Integrity Bypass** (`anti_tampering_integrity_bypass`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- r2frida
- r2

## Standards mapping

- OWASP Mobile Top 10 (2024): M7
- OWASP MASVS: MASVS-RESILIENCE-3
- OWASP MASWE: MASWE-0057
- OWASP MASTG (v2 tests): MASTG-TEST-0338, MASTG-TEST-0387
- OWASP MASTG demos: MASTG-DEMO-0101, MASTG-DEMO-0150
- CWE: CWE-354
