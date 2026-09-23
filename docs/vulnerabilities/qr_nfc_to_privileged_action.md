# QR / NFC Scan -> Privileged Action Without Confirmation

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `qr_nfc_to_privileged_action` |
| Category | `native_bridge` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-PLATFORM-3 |
| MASWE | MASWE-0032 |
| CWE | CWE-306, CWE-862, CWE-346 |
| Suggested tools | frida, objection |

## Description

A scanned QR/NFC tag from an untrusted caller is forwarded straight to a privileged action / automation trigger with no user confirmation, so a co-resident app or a planted tag executes it silently (Home Assistant Companion GHSA NFC/QR class).

## Reproduce in the app

DVMA is the harness: open **QR / NFC Scan -> Privileged Action Without Confirmation** (`qr_nfc_to_privileged_action`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- objection

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-PLATFORM-3
- OWASP MASWE: MASWE-0032
- CWE: CWE-306, CWE-862, CWE-346
