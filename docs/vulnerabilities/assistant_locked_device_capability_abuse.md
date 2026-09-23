# System Assistant -> Locked-Device Capability Abuse

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `assistant_locked_device_capability_abuse` |
| Category | `privacy` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M6 |
| MASVS | MASVS-AUTH-1, MASVS-PRIVACY-1 |
| MASWE | MASWE-0018 |
| CWE | CWE-863, CWE-284, CWE-200 |
| Suggested tools | Siri |

## Description

The system assistant surface (Siri / App-Intents / voice shortcuts) exposes sensitive information or performs a privileged capability while the device is LOCKED because the assistant path never re-checks authentication, so a physical attacker reads protected data or triggers an action without unlocking (iOS Siri locked-device disclosure CVE-2026-28856 class).

## Reproduce in the app

DVMA is the harness: open **System Assistant -> Locked-Device Capability Abuse** (`assistant_locked_device_capability_abuse`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- Siri

## Standards mapping

- OWASP Mobile Top 10 (2024): M6
- OWASP MASVS: MASVS-AUTH-1, MASVS-PRIVACY-1
- OWASP MASWE: MASWE-0018
- CWE: CWE-863, CWE-284, CWE-200
