# WebView Cleartext / Mixed-Content Transport Downgrade

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `webview_cleartext_mixed_content_downgrade` |
| Category | `native_bridge` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M5 |
| MASVS | MASVS-NETWORK-1, MASVS-PLATFORM-2 |
| MASWE | MASWE-0026, MASWE-0035 |
| MASTG (v2 tests) | MASTG-TEST-0235, MASTG-TEST-0237 |
| CWE | CWE-319, CWE-311, CWE-829 |
| Suggested tools | mitmproxy, Burp Suite, Wireshark, testssl.sh |

## Description

A WebView opts out of cleartext blocking (android:usesCleartextTraffic / relaxed network-security-config) and relaxes the Mixed Content Policy (setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)), then loads HTTP or mixed content, so a network attacker injects script / downgrades HTTPS->HTTP and escalates to phishing or full app takeover - a WebView-transport failure distinct from app-level cleartext and from WebView XSS (USENIX Security 2026 large-scale HTTP-in-WebView study).

## Reproduce in the app

DVMA is the harness: open **WebView Cleartext / Mixed-Content Transport Downgrade** (`webview_cleartext_mixed_content_downgrade`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- Burp Suite
- Wireshark
- testssl.sh

## Standards mapping

- OWASP Mobile Top 10 (2024): M5
- OWASP MASVS: MASVS-NETWORK-1, MASVS-PLATFORM-2
- OWASP MASWE: MASWE-0026, MASWE-0035
- OWASP MASTG (v2 tests): MASTG-TEST-0235, MASTG-TEST-0237
- CWE: CWE-319, CWE-311, CWE-829
