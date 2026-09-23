# WebView Remote Debugging Enabled

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `webview_remote_debugging_enabled` |
| Category | `native_bridge` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M8 |
| MASVS | MASVS-RESILIENCE-1, MASVS-PLATFORM-2 |
| MASWE | MASWE-0063 |
| MASTG (v2 tests) | MASTG-TEST-0227 |
| CWE | CWE-489, CWE-215, CWE-200 |
| Suggested tools | adb, jadx, chrome://inspect |

## Description

`WebView.setWebContentsDebuggingEnabled(true)` is left on in a production build, so anyone with adb / chrome://inspect access can attach DevTools to the WebView, inspect the DOM/JS, and execute script in the app's web context - reading tokens, cookies, and authentication material. A production-configuration failure the release build should disable (Android WebView MASTG-TEST-0227 class).

## Reproduce in the app

DVMA is the harness: open **WebView Remote Debugging Enabled** (`webview_remote_debugging_enabled`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- jadx
- chrome://inspect

## Standards mapping

- OWASP Mobile Top 10 (2024): M8
- OWASP MASVS: MASVS-RESILIENCE-1, MASVS-PLATFORM-2
- OWASP MASWE: MASWE-0063
- OWASP MASTG (v2 tests): MASTG-TEST-0227
- CWE: CWE-489, CWE-215, CWE-200
