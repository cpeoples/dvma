# App Virtualization / Cloning Detection Not Implemented

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `virtualization_detection_absent` |
| Category | `resilience` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M7 |
| MASVS | MASVS-RESILIENCE-1 |
| MASWE | MASWE-0052 |
| CWE | CWE-693 |
| Suggested tools | frida |

## Description

The app never detects that it is running inside an app-virtualization / cloning container (VirtualApp-style host, dual-app/work-profile clone), where a co-hosted attacker process shares its runtime and can read its memory and files (MASWE-0052, Android-only surface).

## Reproduce in the app

DVMA is the harness: open **App Virtualization / Cloning Detection Not Implemented** (`virtualization_detection_absent`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M7
- OWASP MASVS: MASVS-RESILIENCE-1
- OWASP MASWE: MASWE-0052
- CWE: CWE-693
