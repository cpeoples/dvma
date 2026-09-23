# Cross-Origin Iframe -> Native Bridge (No Main-Frame/Origin Check)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `crossorigin_iframe_to_native_bridge` |
| Category | `native_bridge` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-2, MASVS-CODE-4 |
| MASWE | MASWE-0033 |
| MASTG (v2 tests) | MASTG-TEST-0334, MASTG-TEST-0376 |
| MASTG demos | MASTG-DEMO-0097 |
| CWE | CWE-346, CWE-1021, CWE-668 |
| Suggested tools | mitmproxy, r2frida, frida, objection |

## Description

The JS-bridge message handler does not verify the message came from the main frame / trusted origin, so a cross-origin iframe reaches the bridge, runs JS in the trusted main-frame origin, and exfiltrates the session/access token (Home Assistant Companion CVE-2026-44698 class; Android addJavascriptInterface + iOS WKUserContentController).

## Reproduce in the app

DVMA is the harness: open **Cross-Origin Iframe -> Native Bridge (No Main-Frame/Origin Check)** (`crossorigin_iframe_to_native_bridge`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- r2frida
- frida
- objection

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-2, MASVS-CODE-4
- OWASP MASWE: MASWE-0033
- OWASP MASTG (v2 tests): MASTG-TEST-0334, MASTG-TEST-0376
- OWASP MASTG demos: MASTG-DEMO-0097
- CWE: CWE-346, CWE-1021, CWE-668
