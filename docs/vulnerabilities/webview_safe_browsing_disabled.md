# WebView Safe Browsing Disabled

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `webview_safe_browsing_disabled` |
| Category | `native_bridge` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M8 |
| MASVS | MASVS-PLATFORM-2 |
| MASWE | MASWE-0035 |
| MASTG (v2 tests) | MASTG-TEST-0399 |
| MASTG demos | MASTG-DEMO-0156 |
| CWE | CWE-1188, CWE-693, CWE-829 |
| Suggested tools | jadx, apktool |

## Description

The WebView disables Google Safe Browsing (android:usesCleartextTraffic aside, `EnableSafeBrowsing=false` / `setSafeBrowsingEnabled(false)`), stripping the browser-originated malware/phishing protection, so attacker-controlled navigation to a known-bad URL is loaded with no warning. Distinct from XSS: the app deliberately removes a platform protection from its embedded browser (Android WebView MASTG-TEST-0399 class).

## Reproduce in the app

DVMA is the harness: open **WebView Safe Browsing Disabled** (`webview_safe_browsing_disabled`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- jadx
- apktool

## Standards mapping

- OWASP Mobile Top 10 (2024): M8
- OWASP MASVS: MASVS-PLATFORM-2
- OWASP MASWE: MASWE-0035
- OWASP MASTG (v2 tests): MASTG-TEST-0399
- OWASP MASTG demos: MASTG-DEMO-0156
- CWE: CWE-1188, CWE-693, CWE-829
