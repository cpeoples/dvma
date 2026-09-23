# Typosquatted Dependency

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `typosquatted_dependency` |
| Category | `supply_chain` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M2 |
| MASVS | MASVS-CODE-3 |
| MASWE | MASWE-0048 |
| MASTG (v2 tests) | MASTG-TEST-0272, MASTG-TEST-0273 |
| MASTG demos | MASTG-DEMO-0050, MASTG-DEMO-0052 |
| CWE | CWE-829, CWE-427 |
| Suggested tools | pubspec review, osv-scanner, MobSF |

## Description

Depends on a lookalike package name mimicking a trusted one.

## Reproduce in the app

DVMA is the harness: open **Typosquatted Dependency** (`typosquatted_dependency`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- pubspec review
- osv-scanner
- MobSF

## Standards mapping

- OWASP Mobile Top 10 (2024): M2
- OWASP MASVS: MASVS-CODE-3
- OWASP MASWE: MASWE-0048
- OWASP MASTG (v2 tests): MASTG-TEST-0272, MASTG-TEST-0273
- OWASP MASTG demos: MASTG-DEMO-0050, MASTG-DEMO-0052
- CWE: CWE-829, CWE-427
