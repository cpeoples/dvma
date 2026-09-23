# Notification Content Disclosure via Alternate Surface

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `notification_alternate_surface_disclosure` |
| Category | `privacy` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M6 |
| MASVS | MASVS-PRIVACY-1, MASVS-PLATFORM-3 |
| MASWE | MASWE-0037 |
| MASTG (v2 tests) | MASTG-TEST-0315 |
| MASTG demos | MASTG-DEMO-0078 |
| CWE | CWE-200, CWE-359, CWE-284 |
| Suggested tools |  |

## Description

Sensitive notification content that is redacted on the lock screen is rendered in full on a secondary presentation surface (desktop / DeX mode, widget, companion display) that skips the redaction / access-control boundary, so someone with access to that surface reads hidden notification contents (Samsung DeX CVE-2026-21006 class).

## Reproduce in the app

DVMA is the harness: open **Notification Content Disclosure via Alternate Surface** (`notification_alternate_surface_disclosure`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M6
- OWASP MASVS: MASVS-PRIVACY-1, MASVS-PLATFORM-3
- OWASP MASWE: MASWE-0037
- OWASP MASTG (v2 tests): MASTG-TEST-0315
- OWASP MASTG demos: MASTG-DEMO-0078
- CWE: CWE-200, CWE-359, CWE-284
