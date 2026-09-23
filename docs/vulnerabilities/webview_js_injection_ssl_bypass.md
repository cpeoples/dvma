# WebView JS Injection + SSL-Validation Bypass

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `webview_js_injection_ssl_bypass` |
| Category | `native_bridge` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M5 |
| MASVS | MASVS-NETWORK-1, MASVS-PLATFORM-2 |
| MASWE | MASWE-0027, MASWE-0035 |
| MASTG (v2 tests) | MASTG-TEST-0284 |
| MASTG demos | MASTG-DEMO-0056 |
| CWE | CWE-295, CWE-79, CWE-749 |
| Suggested tools | mitmproxy, Burp Suite, r2frida, frida, testssl.sh |

## Description

The WebView disables/relaxes TLS certificate validation (accept-all handler) while also permitting script injection, so a MITM attacker rewrites the loaded page, injects JavaScript, and escapes the WebView security boundary to reach privileged actions / steal tokens (PayRange CVE-2026-13461 class).

## Reproduce in the app

DVMA is the harness: open **WebView JS Injection + SSL-Validation Bypass** (`webview_js_injection_ssl_bypass`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- Burp Suite
- r2frida
- frida
- testssl.sh

## Standards mapping

- OWASP Mobile Top 10 (2024): M5
- OWASP MASVS: MASVS-NETWORK-1, MASVS-PLATFORM-2
- OWASP MASWE: MASWE-0027, MASWE-0035
- OWASP MASTG (v2 tests): MASTG-TEST-0284
- OWASP MASTG demos: MASTG-DEMO-0056
- CWE: CWE-295, CWE-79, CWE-749
