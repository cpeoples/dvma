# Accept-All TrustManager

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `accept_all_trust_manager` |
| Category | `network` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M5 |
| MASVS | MASVS-NETWORK-1, MASVS-NETWORK-2 |
| MASWE | MASWE-0027 |
| MASTG (v2 tests) | MASTG-TEST-0282, MASTG-TEST-0283 |
| MASTG demos | MASTG-DEMO-0054, MASTG-DEMO-0055 |
| CWE | CWE-295 |
| Suggested tools | mitmproxy, Burp Suite, testssl.sh |

## Description

Custom certificate callback accepts any certificate.

## Reproduce in the app

DVMA is the harness: open **Accept-All TrustManager** (`accept_all_trust_manager`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- Burp Suite
- testssl.sh

## Standards mapping

- OWASP Mobile Top 10 (2024): M5
- OWASP MASVS: MASVS-NETWORK-1, MASVS-NETWORK-2
- OWASP MASWE: MASWE-0027
- OWASP MASTG (v2 tests): MASTG-TEST-0282, MASTG-TEST-0283
- OWASP MASTG demos: MASTG-DEMO-0054, MASTG-DEMO-0055
- CWE: CWE-295
