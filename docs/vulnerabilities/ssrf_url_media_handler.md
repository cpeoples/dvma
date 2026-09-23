# SSRF via URL / Media Handler

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `ssrf_url_media_handler` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-NETWORK-1, MASVS-PLATFORM-3 |
| MASWE | MASWE-0050 |
| CWE | CWE-918, CWE-601 |
| Suggested tools | Burp Suite, mitmproxy |

## Description

An attacker-controlled URL parameter passed into a fetch/media loader is not restricted to an allowlist, so the app can be steered to internal/loopback endpoints (WhatsApp iOS CVE-2026-23866 SSRF-via-URL-scheme class).

## Reproduce in the app

DVMA is the harness: open **SSRF via URL / Media Handler** (`ssrf_url_media_handler`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- Burp Suite
- mitmproxy

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-NETWORK-1, MASVS-PLATFORM-3
- OWASP MASWE: MASWE-0050
- CWE: CWE-918, CWE-601
