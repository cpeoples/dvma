# Companion Device Pairing / Capability Confusion

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `companion_device_pairing_confusion` |
| Category | `system_provider` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-AUTH-1 |
| MASWE | MASWE-0018 |
| CWE | CWE-863, CWE-284, CWE-1188 |
| Suggested tools | adb, drozer, jadx |

## Description

An app pairs with a nearby companion device (watch / peripheral / car / IoT) via CompanionDeviceManager and then treats 'paired' as 'authorized for every capability' - a spoofed or lower-trust device is granted actions it should not have, or the paired-device identity is confused. Pairing establishes a relationship, not per-capability authorization (Android CompanionDeviceManager trusted-device boundary class).

## Reproduce in the app

DVMA is the harness: open **Companion Device Pairing / Capability Confusion** (`companion_device_pairing_confusion`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-AUTH-1
- OWASP MASWE: MASWE-0018
- CWE: CWE-863, CWE-284, CWE-1188
