# Over-Privileged Permissions

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `over_privileged_permissions` |
| Category | `platform` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-PRIVACY-2 |
| MASWE | MASWE-0066 |
| MASTG (v2 tests) | MASTG-TEST-0254, MASTG-TEST-0255 |
| MASTG demos | MASTG-DEMO-0033 |
| CWE | CWE-250, CWE-272 |
| Suggested tools | MobSF |

## Description

Requests broad permissions unrelated to app functionality.

## Reproduce in the app

DVMA is the harness: open **Over-Privileged Permissions** (`over_privileged_permissions`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- MobSF

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-PRIVACY-2
- OWASP MASWE: MASWE-0066
- OWASP MASTG (v2 tests): MASTG-TEST-0254, MASTG-TEST-0255
- OWASP MASTG demos: MASTG-DEMO-0033
- CWE: CWE-250, CWE-272
