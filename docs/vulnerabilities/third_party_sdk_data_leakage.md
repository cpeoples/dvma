# Third-Party SDK Data Leakage

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `third_party_sdk_data_leakage` |
| Category | `storage` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M9 |
| MASVS | MASVS-STORAGE-2, MASVS-PRIVACY-1 |
| MASWE | MASWE-0069 |
| MASTG (v2 tests) | MASTG-TEST-0318, MASTG-TEST-0319 |
| MASTG demos | MASTG-DEMO-0081 |
| CWE | CWE-200, CWE-359 |
| Suggested tools | mitmproxy, Burp Suite, Wireshark, MobSF |

## Description

A stand-in analytics SDK phones home more data than its stated purpose.

## Reproduce in the app

DVMA is the harness: open **Third-Party SDK Data Leakage** (`third_party_sdk_data_leakage`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- Burp Suite
- Wireshark
- MobSF

## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP MASVS: MASVS-STORAGE-2, MASVS-PRIVACY-1
- OWASP MASWE: MASWE-0069
- OWASP MASTG (v2 tests): MASTG-TEST-0318, MASTG-TEST-0319
- OWASP MASTG demos: MASTG-DEMO-0081
- CWE: CWE-200, CWE-359
