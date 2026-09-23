# Vulnerable Dependencies (known CVE)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `vulnerable_dependencies` |
| Category | `code_quality` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M7 |
| MASVS | MASVS-CODE-3 |
| MASWE | MASWE-0044 |
| MASTG (v2 tests) | MASTG-TEST-0272, MASTG-TEST-0273, MASTG-TEST-0274, MASTG-TEST-0275 |
| MASTG demos | MASTG-DEMO-0050, MASTG-DEMO-0051 |
| CWE | CWE-1104, CWE-937 |
| Suggested tools | osv-scanner, dependency-check, cyclonedx, MobSF |

## Description

Bundles a library version with a documented known CVE.

## Reproduce in the app

DVMA is the harness: open **Vulnerable Dependencies (known CVE)** (`vulnerable_dependencies`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- osv-scanner
- dependency-check
- cyclonedx
- MobSF

## Standards mapping

- OWASP Mobile Top 10 (2024): M7
- OWASP MASVS: MASVS-CODE-3
- OWASP MASWE: MASWE-0044
- OWASP MASTG (v2 tests): MASTG-TEST-0272, MASTG-TEST-0273, MASTG-TEST-0274, MASTG-TEST-0275
- OWASP MASTG demos: MASTG-DEMO-0050, MASTG-DEMO-0051
- CWE: CWE-1104, CWE-937
