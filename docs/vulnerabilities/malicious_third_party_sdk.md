# Malicious Third-Party SDK

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `malicious_third_party_sdk` |
| Category | `supply_chain` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M2 |
| MASVS | MASVS-CODE-3, MASVS-PRIVACY-1 |
| MASWE | MASWE-0048 |
| MASTG (v2 tests) | MASTG-TEST-0318, MASTG-TEST-0319 |
| MASTG demos | MASTG-DEMO-0081 |
| CWE | CWE-506, CWE-829 |
| Suggested tools | mitmproxy, Burp Suite, MobSF, JEB |

## Description

A bundled SDK exfiltrates data far beyond its stated purpose.

## Reproduce in the app

DVMA is the harness: open **Malicious Third-Party SDK** (`malicious_third_party_sdk`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- Burp Suite
- MobSF
- JEB

## Standards mapping

- OWASP Mobile Top 10 (2024): M2
- OWASP MASVS: MASVS-CODE-3, MASVS-PRIVACY-1
- OWASP MASWE: MASWE-0048
- OWASP MASTG (v2 tests): MASTG-TEST-0318, MASTG-TEST-0319
- OWASP MASTG demos: MASTG-DEMO-0081
- CWE: CWE-506, CWE-829
