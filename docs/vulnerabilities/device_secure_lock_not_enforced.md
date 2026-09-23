# Device Secure Lock Not Enforced for Sensitive Storage

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `device_secure_lock_not_enforced` |
| Category | `crypto` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M9 |
| MASVS | MASVS-CRYPTO-2, MASVS-STORAGE-1 |
| MASWE | MASWE-0017 |
| CWE | CWE-311, CWE-522 |
| Suggested tools | frida |

## Description

A secret is persisted without requiring a device secure lock (PIN/passcode/biometric) or binding the key to it, so on a device with no lock screen the secret is recoverable at rest with no user presence.

## Reproduce in the app

DVMA is the harness: open **Device Secure Lock Not Enforced for Sensitive Storage** (`device_secure_lock_not_enforced`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP MASVS: MASVS-CRYPTO-2, MASVS-STORAGE-1
- OWASP MASWE: MASWE-0017
- CWE: CWE-311, CWE-522
