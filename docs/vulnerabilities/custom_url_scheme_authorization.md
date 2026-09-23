# Custom URL Scheme Authorization (arbitrary URL load)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `custom_url_scheme_authorization` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-3, MASVS-CODE-4 |
| MASWE | MASWE-0029 |
| MASTG (v2 tests) | MASTG-TEST-0371, MASTG-TEST-0370 |
| MASTG demos | MASTG-DEMO-0134, MASTG-DEMO-0135 |
| CWE | CWE-939, CWE-862, CWE-601 |
| Suggested tools |  |

## Description

A custom URL-scheme handler loads a caller-supplied URL without checking the caller or an allowlist, so any co-resident app can make DVMA display an attacker site (Rakuten CVE-2024-41918 / @cosme CVE-2024-45203 / Skylark CVE-2024-54014 / Groww CVE-2026-12065 class).

## Reproduce in the app

DVMA is the harness: open **Custom URL Scheme Authorization (arbitrary URL load)** (`custom_url_scheme_authorization`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-3, MASVS-CODE-4
- OWASP MASWE: MASWE-0029
- OWASP MASTG (v2 tests): MASTG-TEST-0371, MASTG-TEST-0370
- OWASP MASTG demos: MASTG-DEMO-0134, MASTG-DEMO-0135
- CWE: CWE-939, CWE-862, CWE-601
