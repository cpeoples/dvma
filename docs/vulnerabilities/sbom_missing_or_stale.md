# Missing / Stale SBOM (No Component Inventory)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `sbom_missing_or_stale` |
| Category | `supply_chain` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M2 |
| MASVS | MASVS-CODE-3, MASVS-CODE-1 |
| MASWE | MASWE-0044 |
| MASTG (v2 tests) | MASTG-TEST-0274, MASTG-TEST-0275 |
| MASTG demos | MASTG-DEMO-0051, MASTG-DEMO-0053 |
| CWE | CWE-1104, CWE-1035 |
| Suggested tools | cyclonedx, osv-scanner, pubspec review |

## Description

No Software Bill of Materials is produced, so bundled SDKs and their known-vulnerable versions are invisible to defenders.

## Reproduce in the app

DVMA is the harness: open **Missing / Stale SBOM (No Component Inventory)** (`sbom_missing_or_stale`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- cyclonedx
- osv-scanner
- pubspec review

## Standards mapping

- OWASP Mobile Top 10 (2024): M2
- OWASP MASVS: MASVS-CODE-3, MASVS-CODE-1
- OWASP MASWE: MASWE-0044
- OWASP MASTG (v2 tests): MASTG-TEST-0274, MASTG-TEST-0275
- OWASP MASTG demos: MASTG-DEMO-0051, MASTG-DEMO-0053
- CWE: CWE-1104, CWE-1035
