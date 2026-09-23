# Lock-Screen Control / Widget Action Authorization

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `lockscreen_control_action_authorization` |
| Category | `system_provider` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-AUTH-1, MASVS-PLATFORM-1 |
| MASWE | MASWE-0018 |
| CWE | CWE-862, CWE-284, CWE-863 |
| Suggested tools | frida, objection, idb |

## Description

A Control Widget / interactive widget exposed on the Lock Screen, Control Center, or Action Button invokes a sensitive App Intent without the authentication the full app would require, so a physically-present attacker triggers a privileged operation from a locked device. The question is whether a system surface can invoke a sensitive op without the app's own auth gate (Apple WidgetKit Control lock-screen action-authorization class).

## Reproduce in the app

DVMA is the harness: open **Lock-Screen Control / Widget Action Authorization** (`lockscreen_control_action_authorization`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- objection
- idb

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-AUTH-1, MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0018
- CWE: CWE-862, CWE-284, CWE-863
