# In-App Browser UI / Address-Bar Spoofing

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `inapp_browser_ui_spoofing` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-2 |
| MASWE | MASWE-0035 |
| CWE | CWE-1021, CWE-451 |
| Suggested tools | frida, objection |

## Description

An in-app WebView browser derives the displayed origin/address-bar from attacker-controllable content instead of the real committed URL, enabling website spoofing / UI misrepresentation (Firefox Focus CVE-2025-10290 / LINE CVE-2024-5739 trust class).

## Reproduce in the app

DVMA is the harness: open **In-App Browser UI / Address-Bar Spoofing** (`inapp_browser_ui_spoofing`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- objection

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-2
- OWASP MASWE: MASWE-0035
- CWE: CWE-1021, CWE-451
