# Cleartext Traffic Allowed

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `cleartext_traffic_allowed` |
| Category | `network` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M5 |
| MASVS | MASVS-NETWORK-1 |
| MASWE | MASWE-0026 |
| MASTG (v2 tests) | MASTG-TEST-0235, MASTG-TEST-0237, MASTG-TEST-0238, MASTG-TEST-0322, MASTG-TEST-0233 |
| MASTG demos | MASTG-DEMO-0083 |
| CWE | CWE-319 |
| Suggested tools | mitmproxy, Wireshark, Burp Suite |

## Description

App sends requests over plain HTTP; cleartext permitted in manifest/plist.

## Reproduce in the app

DVMA is the harness: open **Cleartext Traffic Allowed** (`cleartext_traffic_allowed`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- Wireshark
- Burp Suite

## Standards mapping

- OWASP Mobile Top 10 (2024): M5
- OWASP MASVS: MASVS-NETWORK-1
- OWASP MASWE: MASWE-0026
- OWASP MASTG (v2 tests): MASTG-TEST-0235, MASTG-TEST-0237, MASTG-TEST-0238, MASTG-TEST-0322, MASTG-TEST-0233
- OWASP MASTG demos: MASTG-DEMO-0083
- CWE: CWE-319
