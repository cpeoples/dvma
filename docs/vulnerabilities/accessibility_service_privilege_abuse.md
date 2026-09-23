# AccessibilityService Privilege Abuse

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `accessibility_service_privilege_abuse` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-AUTH-1 |
| MASWE | MASWE-0040 |
| CWE | CWE-862, CWE-284, CWE-441 |
| Suggested tools | adb, accessibility inspector, jadx, drozer |

## Description

An AccessibilityService performs a privileged action (launching an activity from the background, hiding/suppressing UI, injecting a gesture/click) with insufficient caller / service-state validation, so the a11y capability is abused for privilege escalation or UI manipulation (Android AccessibilityServiceConnection CVE-2025-26462 / CVE-2023-21109 class).

## Reproduce in the app

DVMA is the harness: open **AccessibilityService Privilege Abuse** (`accessibility_service_privilege_abuse`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- accessibility inspector
- jadx
- drozer

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-AUTH-1
- OWASP MASWE: MASWE-0040
- CWE: CWE-862, CWE-284, CWE-441
