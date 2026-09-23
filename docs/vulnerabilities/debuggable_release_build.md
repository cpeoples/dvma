# Debuggable Release Build

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `debuggable_release_build` |
| Category | `code_quality` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M7 |
| MASVS | MASVS-RESILIENCE-4, MASVS-CODE-2 |
| MASWE | MASWE-0063 |
| MASTG (v2 tests) | MASTG-TEST-0226, MASTG-TEST-0261 |
| MASTG demos | MASTG-DEMO-0040, MASTG-DEMO-0036 |
| CWE | CWE-489 |
| Suggested tools | MobSF |

## Description

Release build ships with debuggable=true / debug flags left on.

## Reproduce in the app

DVMA is the harness: open **Debuggable Release Build** (`debuggable_release_build`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- MobSF

## Standards mapping

- OWASP Mobile Top 10 (2024): M7
- OWASP MASVS: MASVS-RESILIENCE-4, MASVS-CODE-2
- OWASP MASWE: MASWE-0063
- OWASP MASTG (v2 tests): MASTG-TEST-0226, MASTG-TEST-0261
- OWASP MASTG demos: MASTG-DEMO-0040, MASTG-DEMO-0036
- CWE: CWE-489
