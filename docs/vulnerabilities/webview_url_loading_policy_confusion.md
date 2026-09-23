# WebView URL-Loading Policy Confusion

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `webview_url_loading_policy_confusion` |
| Category | `native_bridge` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-2, MASVS-CODE-4 |
| MASWE | MASWE-0035 |
| MASTG (v2 tests) | MASTG-TEST-0332, MASTG-TEST-0398 |
| MASTG demos | MASTG-DEMO-0157 |
| CWE | CWE-20, CWE-441, CWE-939 |
| Suggested tools | mitmproxy, frida, objection |

## Description

The WebView's URL-policy handler (`shouldOverrideUrlLoading` / `decidePolicyForNavigationAction`) makes a trust decision on a raw, un-canonicalized URL, so scheme/host confusion (`javascript:`, `file:`, `content:`, a custom scheme, a redirect, or a malformed URL) slips past the allow/deny logic and loads privileged content. The bug is the policy IMPLEMENTATION, not merely calling loadUrl (Android/iOS URL-loading-handler MASTG-TEST-0332 class).

## Reproduce in the app

DVMA is the harness: open **WebView URL-Loading Policy Confusion** (`webview_url_loading_policy_confusion`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- frida
- objection

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-2, MASVS-CODE-4
- OWASP MASWE: MASWE-0035
- OWASP MASTG (v2 tests): MASTG-TEST-0332, MASTG-TEST-0398
- OWASP MASTG demos: MASTG-DEMO-0157
- CWE: CWE-20, CWE-441, CWE-939
