# Insecure WebView (JS Bridge RCE, file:// access)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `insecure_webview` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-2 |
| MASWE | MASWE-0033, MASWE-0034 |
| MASTG (v2 tests) | MASTG-TEST-0334, MASTG-TEST-0333, MASTG-TEST-0250 |
| MASTG demos | MASTG-DEMO-0097, MASTG-DEMO-0096 |
| CWE | CWE-749, CWE-79 |
| Suggested tools | mitmproxy, r2frida, frida, objection |

## Description

WebView exposes a JS bridge and enables file:// access for RCE-style abuse.

## Reproduce in the app

DVMA is the harness: open **Insecure WebView (JS Bridge RCE, file:// access)** (`insecure_webview`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- r2frida
- frida
- objection

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-2
- OWASP MASWE: MASWE-0033, MASWE-0034
- OWASP MASTG (v2 tests): MASTG-TEST-0334, MASTG-TEST-0333, MASTG-TEST-0250
- OWASP MASTG demos: MASTG-DEMO-0097, MASTG-DEMO-0096
- CWE: CWE-749, CWE-79
