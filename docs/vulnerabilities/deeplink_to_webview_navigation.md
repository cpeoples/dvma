# Deep Link -> Trusted WebView Navigation

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `deeplink_to_webview_navigation` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-2, MASVS-PLATFORM-1 |
| MASWE | MASWE-0035, MASWE-0029 |
| MASTG (v2 tests) | MASTG-TEST-0332, MASTG-TEST-0027 |
| MASTG demos | MASTG-DEMO-0095 |
| CWE | CWE-939, CWE-601, CWE-749 |
| Suggested tools |  |

## Description

A URL parameter from an incoming deep link/intent is loaded straight into a trusted WebView with no origin allowlist, so an attacker renders arbitrary content in-app (TikTok CVE-2024-45240 / Rakuten CVE-2024-41918 / EcoOnline CVE-2026-26897 class).

## Reproduce in the app

DVMA is the harness: open **Deep Link -> Trusted WebView Navigation** (`deeplink_to_webview_navigation`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-2, MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0035, MASWE-0029
- OWASP MASTG (v2 tests): MASTG-TEST-0332, MASTG-TEST-0027
- OWASP MASTG demos: MASTG-DEMO-0095
- CWE: CWE-939, CWE-601, CWE-749
