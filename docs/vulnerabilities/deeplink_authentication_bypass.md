# Deep Link Authentication Bypass

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `deeplink_authentication_bypass` |
| Category | `auth` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-1, MASVS-PLATFORM-1 |
| MASWE | MASWE-0018, MASWE-0029 |
| MASTG (v2 tests) | MASTG-TEST-0371, MASTG-TEST-0370 |
| MASTG demos | MASTG-DEMO-0134, MASTG-DEMO-0135 |
| CWE | CWE-288, CWE-306, CWE-939 |
| Suggested tools |  |

## Description

A deep link routes directly to an authenticated screen/function, skipping the app-lock / login gate the normal navigation path enforces (Groww CVE-2026-12065 class).

## Reproduce in the app

DVMA is the harness: open **Deep Link Authentication Bypass** (`deeplink_authentication_bypass`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-1, MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0018, MASWE-0029
- OWASP MASTG (v2 tests): MASTG-TEST-0371, MASTG-TEST-0370
- OWASP MASTG demos: MASTG-DEMO-0134, MASTG-DEMO-0135
- CWE: CWE-288, CWE-306, CWE-939
