# WebView Origin Confusion -> Local-Only IPC

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `webview_origin_confusion_ipc` |
| Category | `native_bridge` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-2, MASVS-CODE-4 |
| MASWE | MASWE-0034 |
| MASTG (v2 tests) | MASTG-TEST-0334 |
| CWE | CWE-346, CWE-863, CWE-441 |
| Suggested tools | mitmproxy, r2frida, frida |

## Description

The WebView IPC layer classifies the caller's origin incorrectly, so a remote page is treated as the local/trusted application origin and can invoke local-only, privileged IPC commands it should never reach (Tauri WebView IPC origin confusion CVE-2026-42184 class).

## Reproduce in the app

DVMA is the harness: open **WebView Origin Confusion -> Local-Only IPC** (`webview_origin_confusion_ipc`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- r2frida
- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-2, MASVS-CODE-4
- OWASP MASWE: MASWE-0034
- OWASP MASTG (v2 tests): MASTG-TEST-0334
- CWE: CWE-346, CWE-863, CWE-441
