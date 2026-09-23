# TOCTOU Race Condition in Auth Check

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `toctou_race_condition` |
| Category | `resilience` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M7 |
| MASVS | MASVS-AUTH-1, MASVS-CODE-4 |
| MASWE | MASWE-0018 |
| CWE | CWE-367 |
| Suggested tools | frida, r2frida, frida-trace |

## Description

Auth is checked then used with a mutable gap an attacker can win.

## Reproduce in the app

DVMA is the harness: open **TOCTOU Race Condition in Auth Check** (`toctou_race_condition`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- r2frida
- frida-trace

## Standards mapping

- OWASP Mobile Top 10 (2024): M7
- OWASP MASVS: MASVS-AUTH-1, MASVS-CODE-4
- OWASP MASWE: MASWE-0018
- CWE: CWE-367
