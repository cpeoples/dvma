# Cross-App Browser History Access

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `cross_app_browser_history_access` |
| Category | `privacy` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M6 |
| MASVS | MASVS-PRIVACY-1, MASVS-STORAGE-2 |
| MASWE | MASWE-0002 |
| MASTG (v2 tests) | MASTG-TEST-0007 |
| CWE | CWE-200, CWE-359 |
| Suggested tools | frida, sqlite3 |

## Description

The app reads browsing history that belongs to another app / the system browser (a shared or world-readable history store) with no user consent, exposing the user's Safari/browser history across a privacy boundary (iOS CVE-2026-20656 Safari-history access class).

## Reproduce in the app

DVMA is the harness: open **Cross-App Browser History Access** (`cross_app_browser_history_access`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- sqlite3

## Standards mapping

- OWASP Mobile Top 10 (2024): M6
- OWASP MASVS: MASVS-PRIVACY-1, MASVS-STORAGE-2
- OWASP MASWE: MASWE-0002
- OWASP MASTG (v2 tests): MASTG-TEST-0007
- CWE: CWE-200, CWE-359
