# Activity-Alias Exposure

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `activity_alias_exposure` |
| Category | `platform` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1 |
| MASWE | MASWE-0032, MASWE-0018 |
| MASTG (v2 tests) | MASTG-TEST-0364 |
| MASTG demos | MASTG-DEMO-0128 |
| CWE | CWE-926, CWE-200, CWE-284 |
| Suggested tools | adb, drozer, jadx, apktool |

## Description

A protected/internal Activity is left reachable through an `<activity-alias>` that is `exported=true` (or lacks the target's permission), so an attacker launches the sensitive Activity via the alias even though the real component appears protected. A manifest-level, deterministic mistake: the alias is a second, unguarded entry point (Android activity-alias exposure class).

## Reproduce in the app

DVMA is the harness: open **Activity-Alias Exposure** (`activity_alias_exposure`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx
- apktool

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0032, MASWE-0018
- OWASP MASTG (v2 tests): MASTG-TEST-0364
- OWASP MASTG demos: MASTG-DEMO-0128
- CWE: CWE-926, CWE-200, CWE-284
