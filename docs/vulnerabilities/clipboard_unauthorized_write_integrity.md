# Clipboard Unauthorized Write / Integrity Tampering

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `clipboard_unauthorized_write_integrity` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-2, MASVS-CODE-4 |
| MASWE | MASWE-0030 |
| CWE | CWE-345, CWE-471, CWE-668 |
| Suggested tools |  |

## Description

Untrusted content (a page loaded in the app's WebView, or another app) can OVERWRITE the system clipboard through the app with no user gesture / origin check, so what the user later pastes is attacker-controlled - a clipboard integrity failure distinct from clipboard read/leak (Lenovo Android web-to-clipboard CVE-2026-7516 class).

## Reproduce in the app

DVMA is the harness: open **Clipboard Unauthorized Write / Integrity Tampering** (`clipboard_unauthorized_write_integrity`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-2, MASVS-CODE-4
- OWASP MASWE: MASWE-0030
- CWE: CWE-345, CWE-471, CWE-668
