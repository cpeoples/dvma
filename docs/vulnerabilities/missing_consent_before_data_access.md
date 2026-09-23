# Missing Consent Before Data Access

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `missing_consent_before_data_access` |
| Category | `privacy` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M6 |
| MASVS | MASVS-PRIVACY-1, MASVS-PRIVACY-2 |
| MASWE | MASWE-0078 |
| MASTG (v2 tests) | MASTG-TEST-0360, MASTG-TEST-0256 |
| MASTG demos | MASTG-DEMO-0126 |
| CWE | CWE-359 |
| Suggested tools | mitmproxy, Burp Suite, frida |

## Description

Accesses location/contacts/photos with no consent screen.

## Reproduce in the app

DVMA is the harness: open **Missing Consent Before Data Access** (`missing_consent_before_data_access`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- Burp Suite
- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M6
- OWASP MASVS: MASVS-PRIVACY-1, MASVS-PRIVACY-2
- OWASP MASWE: MASWE-0078
- OWASP MASTG (v2 tests): MASTG-TEST-0360, MASTG-TEST-0256
- OWASP MASTG demos: MASTG-DEMO-0126
- CWE: CWE-359
