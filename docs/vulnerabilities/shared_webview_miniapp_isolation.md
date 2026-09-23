# Shared WebView Mini-App Isolation Failure (Cross-Tenant Cookies)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `shared_webview_miniapp_isolation` |
| Category | `native_bridge` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-2, MASVS-STORAGE-2 |
| MASWE | MASWE-0034 |
| CWE | CWE-346, CWE-668, CWE-200 |
| Suggested tools | r2frida, frida, objection, sqlite3 |

## Description

A super-app hosts multiple mini-programs in ONE shared WebView instance (shared cookie jar / localStorage), so one mini-app reads another mini-app's cookies and storage - a cross-tenant isolation failure enabling data exfiltration between mini-apps (WeChat/Alipay/TikTok/Baidu cross-mini-program cookie-sharing research).

## Reproduce in the app

DVMA is the harness: open **Shared WebView Mini-App Isolation Failure (Cross-Tenant Cookies)** (`shared_webview_miniapp_isolation`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- r2frida
- frida
- objection
- sqlite3

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-2, MASVS-STORAGE-2
- OWASP MASWE: MASWE-0034
- CWE: CWE-346, CWE-668, CWE-200
