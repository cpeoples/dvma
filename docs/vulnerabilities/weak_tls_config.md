# Weak / Outdated TLS Config

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `weak_tls_config` |
| Category | `network` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M5 |
| MASVS | MASVS-NETWORK-1 |
| MASWE | MASWE-0026 |
| MASTG (v2 tests) | MASTG-TEST-0217, MASTG-TEST-0218, MASTG-TEST-0348 |
| MASTG demos | MASTG-DEMO-0110 |
| CWE | CWE-326, CWE-327 |
| Suggested tools | testssl.sh, mitmproxy, Wireshark |

## Description

Negotiates deprecated TLS versions / weak cipher suites.

## Reproduce in the app

DVMA is the harness: open **Weak / Outdated TLS Config** (`weak_tls_config`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- testssl.sh
- mitmproxy
- Wireshark

## Standards mapping

- OWASP Mobile Top 10 (2024): M5
- OWASP MASVS: MASVS-NETWORK-1
- OWASP MASWE: MASWE-0026
- OWASP MASTG (v2 tests): MASTG-TEST-0217, MASTG-TEST-0218, MASTG-TEST-0348
- OWASP MASTG demos: MASTG-DEMO-0110
- CWE: CWE-326, CWE-327
