# Device Attestation Not Implemented (Play Integrity / App Attest)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `device_attestation_absent` |
| Category | `resilience` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M7 |
| MASVS | MASVS-RESILIENCE-1 |
| MASWE | MASWE-0054 |
| CWE | CWE-693 |
| Suggested tools | frida |

## Description

The app trusts the client environment without requesting a hardware-backed device-integrity verdict (Play Integrity on Android, DeviceCheck/App Attest on iOS), so a rooted, emulated, or tampered device is treated as genuine (MASWE-0054).

## Reproduce in the app

DVMA is the harness: open **Device Attestation Not Implemented (Play Integrity / App Attest)** (`device_attestation_absent`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M7
- OWASP MASVS: MASVS-RESILIENCE-1
- OWASP MASWE: MASWE-0054
- CWE: CWE-693
