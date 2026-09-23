# Insecure WebView Networking

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `insecure_webview_networking` |
| Category | `network` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M5 |
| MASVS | MASVS-NETWORK-1, MASVS-PLATFORM-2 |
| MASWE | MASWE-0026 |
| MASTG (v2 tests) | MASTG-TEST-0237, MASTG-TEST-0238, MASTG-TEST-0235 |
| CWE | CWE-319, CWE-295 |
| Suggested tools | mitmproxy, Burp Suite |

## Description

WebView ignores network security config and loads mixed/cleartext content.

## Reproduce in the app

DVMA is the harness: open **Insecure WebView Networking** (`insecure_webview_networking`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- Burp Suite

## Standards mapping

- OWASP Mobile Top 10 (2024): M5
- OWASP MASVS: MASVS-NETWORK-1, MASVS-PLATFORM-2
- OWASP MASWE: MASWE-0026
- OWASP MASTG (v2 tests): MASTG-TEST-0237, MASTG-TEST-0238, MASTG-TEST-0235
- CWE: CWE-319, CWE-295
