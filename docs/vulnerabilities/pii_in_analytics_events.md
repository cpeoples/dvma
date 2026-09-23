# PII in Analytics Events

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `pii_in_analytics_events` |
| Category | `privacy` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M6 |
| MASVS | MASVS-PRIVACY-1 |
| MASWE | MASWE-0069 |
| MASTG (v2 tests) | MASTG-TEST-0318, MASTG-TEST-0319 |
| MASTG demos | MASTG-DEMO-0081 |
| CWE | CWE-359, CWE-200 |
| Suggested tools | mitmproxy, Burp Suite, Wireshark |

## Description

Raw PII (email, precise location) sent unfiltered in analytics events.

## Reproduce in the app

DVMA is the harness: open **PII in Analytics Events** (`pii_in_analytics_events`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- Burp Suite
- Wireshark

## Standards mapping

- OWASP Mobile Top 10 (2024): M6
- OWASP MASVS: MASVS-PRIVACY-1
- OWASP MASWE: MASWE-0069
- OWASP MASTG (v2 tests): MASTG-TEST-0318, MASTG-TEST-0319
- OWASP MASTG demos: MASTG-DEMO-0081
- CWE: CWE-359, CWE-200
