# WebView SOP / CSP Disabled (Cross-Origin & Inline Script)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `webview_sop_csp_disabled` |
| Category | `native_bridge` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-2, MASVS-CODE-4 |
| MASWE | MASWE-0034 |
| MASTG (v2 tests) | MASTG-TEST-0335, MASTG-TEST-0333 |
| MASTG demos | MASTG-DEMO-0096 |
| CWE | CWE-346, CWE-79, CWE-829 |
| Suggested tools | mitmproxy, r2frida, frida |

## Description

The app's WebView relaxes/omits Same-Origin-Policy and Content-Security-Policy enforcement (e.g. allowUniversalAccessFromFileURLs / allowFileAccessFromFileURLs, no CSP on loaded content), so cross-origin reads and inline/injected script execute in the trusted app origin (WebKit SOP-bypass CVE-2026-20643 / CSP-bypass CVE-2026-20665 app-level analog).

## Reproduce in the app

DVMA is the harness: open **WebView SOP / CSP Disabled (Cross-Origin & Inline Script)** (`webview_sop_csp_disabled`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- r2frida
- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-2, MASVS-CODE-4
- OWASP MASWE: MASWE-0034
- OWASP MASTG (v2 tests): MASTG-TEST-0335, MASTG-TEST-0333
- OWASP MASTG demos: MASTG-DEMO-0096
- CWE: CWE-346, CWE-79, CWE-829
