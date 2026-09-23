# QR Code Injection

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `qr_code_injection` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-CODE-4 |
| MASWE | MASWE-0050 |
| CWE | CWE-20 |
| Suggested tools | adb, frida |

## Description

Scanner trusts scanned content and acts on it without validation.

## Reproduce in the app

DVMA is the harness: open **QR Code Injection** (`qr_code_injection`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-CODE-4
- OWASP MASWE: MASWE-0050
- CWE: CWE-20
