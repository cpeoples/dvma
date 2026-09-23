# Deep Link / URL Scheme Hijack

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `deeplink_url_scheme_hijack` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1 |
| MASWE | MASWE-0029 |
| MASTG (v2 tests) | MASTG-TEST-0028, MASTG-TEST-0393, MASTG-TEST-0371 |
| MASTG demos | MASTG-DEMO-0151 |
| CWE | CWE-939, CWE-20 |
| Suggested tools |  |

## Description

Custom scheme is unvalidated and can be claimed/abused by another app.

## Reproduce in the app

DVMA is the harness: open **Deep Link / URL Scheme Hijack** (`deeplink_url_scheme_hijack`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0029
- OWASP MASTG (v2 tests): MASTG-TEST-0028, MASTG-TEST-0393, MASTG-TEST-0371
- OWASP MASTG demos: MASTG-DEMO-0151
- CWE: CWE-939, CWE-20
