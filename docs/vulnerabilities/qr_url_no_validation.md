# QR Scanner -> URL With No Validation

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `qr_url_no_validation` |
| Category | `platform` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-3, MASVS-CODE-4 |
| MASWE | MASWE-0050 |
| CWE | CWE-601, CWE-20 |
| Suggested tools | frida |

## Description

A scanned QR code's payload is treated as a trusted URL/deeplink and opened/navigated without validation (Firefox iOS QR-scanner CVE-2025-54145 class).

## Reproduce in the app

DVMA is the harness: open **QR Scanner -> URL With No Validation** (`qr_url_no_validation`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-3, MASVS-CODE-4
- OWASP MASWE: MASWE-0050
- CWE: CWE-601, CWE-20
