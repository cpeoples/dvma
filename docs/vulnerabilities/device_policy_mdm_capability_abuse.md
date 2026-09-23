# Device Policy / MDM Capability Abuse

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `device_policy_mdm_capability_abuse` |
| Category | `system_provider` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-AUTH-1 |
| MASWE | MASWE-0018 |
| CWE | CWE-862, CWE-269, CWE-841 |
| Suggested tools | adb, drozer, jadx |

## Description

A Device Admin / DevicePolicyManager receiver acts as a device-wide policy authority but validates policy parameters or caller/state insufficiently, so app-controlled policy changes, work-profile boundary confusion, or policy-state desync escalate privilege or cause DoS across the device. The DPC's authority - not just 'DeviceAdmin used' - is the boundary (Android DevicePolicyManagerService logic-flaw CVE-2025-48553 class).

## Reproduce in the app

DVMA is the harness: open **Device Policy / MDM Capability Abuse** (`device_policy_mdm_capability_abuse`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-AUTH-1
- OWASP MASWE: MASWE-0018
- CWE: CWE-862, CWE-269, CWE-841
