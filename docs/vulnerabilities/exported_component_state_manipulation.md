# Exported Component -> Unauthorized State Manipulation

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `exported_component_state_manipulation` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-AUTH-1 |
| MASWE | MASWE-0032, MASWE-0018 |
| MASTG (v2 tests) | MASTG-TEST-0364 |
| MASTG demos | MASTG-DEMO-0128 |
| CWE | CWE-862, CWE-639, CWE-284 |
| Suggested tools | adb, drozer, jadx |

## Description

An exported component accepts an attacker-controlled identifier in its intent extras and performs a security-sensitive STATE CHANGE (e.g. cancelling the victim's AI-chat notification) with no caller/ownership validation, so any co-resident app mutates state it does not own (Datadog Android CVE-2026-47361 class).

## Reproduce in the app

DVMA is the harness: open **Exported Component -> Unauthorized State Manipulation** (`exported_component_state_manipulation`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-AUTH-1
- OWASP MASWE: MASWE-0032, MASWE-0018
- OWASP MASTG (v2 tests): MASTG-TEST-0364
- OWASP MASTG demos: MASTG-DEMO-0128
- CWE: CWE-862, CWE-639, CWE-284
