# WebView Untrusted URL -> Local File Read (iOS WKWebView)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `wkwebview_untrusted_url_local_file` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-2, MASVS-STORAGE-2 |
| MASWE | MASWE-0034, MASWE-0035 |
| MASTG (v2 tests) | MASTG-TEST-0333, MASTG-TEST-0332 |
| MASTG demos | MASTG-DEMO-0096 |
| CWE | CWE-79, CWE-73, CWE-200 |
| Suggested tools | objection, frida, r2frida, ipsw, class-dump, Hopper, r2ghidra, Ghidra |

## Description

Unsanitized user-controlled fields are reflected into a WebView, and file access is left enabled, so injected JS can read the app's local files from the WebView context (ZOLL ePCR iOS CVE-2025-12699 class).

## Reproduce in the app

DVMA is the harness: open **WebView Untrusted URL -> Local File Read (iOS WKWebView)** (`wkwebview_untrusted_url_local_file`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- objection
- frida
- r2frida
- ipsw
- class-dump
- Hopper
- r2ghidra
- Ghidra

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-2, MASVS-STORAGE-2
- OWASP MASWE: MASWE-0034, MASWE-0035
- OWASP MASTG (v2 tests): MASTG-TEST-0333, MASTG-TEST-0332
- OWASP MASTG demos: MASTG-DEMO-0096
- CWE: CWE-79, CWE-73, CWE-200
