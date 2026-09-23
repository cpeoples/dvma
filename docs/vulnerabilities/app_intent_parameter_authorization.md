# App Intent / Siri Parameter -> Privileged Action (No Authz)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `app_intent_parameter_authorization` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-3, MASVS-AUTH-1 |
| MASWE | MASWE-0018 |
| CWE | CWE-862, CWE-639, CWE-20 |
| Suggested tools | Siri |

## Description

An App Intent / Siri / Shortcuts / Spotlight entry point maps an untrusted, system-supplied parameter straight to a privileged app action (transfer, delete, export) with no per-invocation authorization or ownership check, so a crafted shortcut invokes the action on the user's behalf (Apple App Intents capability-confusion class).

## Reproduce in the app

DVMA is the harness: open **App Intent / Siri Parameter -> Privileged Action (No Authz)** (`app_intent_parameter_authorization`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- Siri

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-3, MASVS-AUTH-1
- OWASP MASWE: MASWE-0018
- CWE: CWE-862, CWE-639, CWE-20
