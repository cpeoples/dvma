# Dependency Confusion / Substitution

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `dependency_confusion` |
| Category | `supply_chain` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M2 |
| MASVS | MASVS-CODE-3, MASVS-CODE-1 |
| MASWE | MASWE-0048 |
| CWE | CWE-427, CWE-1357, CWE-494 |
| Suggested tools | pubspec review, osv-scanner |

## Description

An internal/private package name is resolved from a public registry, so an attacker who publishes that name to the public index gets their impostor pulled into the build (iOS dependency-management research; classic dependency-confusion class).

## Reproduce in the app

DVMA is the harness: open **Dependency Confusion / Substitution** (`dependency_confusion`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- pubspec review
- osv-scanner

## Standards mapping

- OWASP Mobile Top 10 (2024): M2
- OWASP MASVS: MASVS-CODE-3, MASVS-CODE-1
- OWASP MASWE: MASWE-0048
- CWE: CWE-427, CWE-1357, CWE-494
