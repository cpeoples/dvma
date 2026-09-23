# Activity Task-Stack / Affinity Hijacking

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `activity_task_stack_hijacking` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-PLATFORM-3 |
| MASWE | MASWE-0032 |
| CWE | CWE-1021, CWE-451, CWE-346 |
| Suggested tools | adb, drozer, jadx |

## Description

Loose task affinity / launch modes (`singleTask` + shared `taskAffinity`, allowTaskReparenting) let a malicious Activity insert itself into a trusted app's task/back-stack (StrandHogg-style), so the attacker screen appears inside the victim's flow for phishing / UI-trust confusion. Distinct from tapjacking (this is task-stack placement, not an overlay) (Android task-hijacking class).

## Reproduce in the app

DVMA is the harness: open **Activity Task-Stack / Affinity Hijacking** (`activity_task_stack_hijacking`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-PLATFORM-3
- OWASP MASWE: MASWE-0032
- CWE: CWE-1021, CWE-451, CWE-346
