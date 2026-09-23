# MediaProjection / Screen-Capture Authorization Bypass

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `mediaprojection_screencapture_authorization_bypass` |
| Category | `system_provider` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-PRIVACY-1 |
| MASWE | MASWE-0038 |
| CWE | CWE-20, CWE-862, CWE-200 |
| Suggested tools | adb, drozer, jadx, scrcpy |

## Description

An attacker-controlled value flows into MediaProjection / screen-capture authorization (a reused/forwarded projection token, a consent-result treated as authoritative without validation), so an app gains unauthorized screen-recording capability or a capture token leaks to another app (Android MediaProjection authorization-bypass CVE-2025-32322 class).

## Reproduce in the app

DVMA is the harness: open **MediaProjection / Screen-Capture Authorization Bypass** (`mediaprojection_screencapture_authorization_bypass`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx
- scrcpy

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-PRIVACY-1
- OWASP MASWE: MASWE-0038
- CWE: CWE-20, CWE-862, CWE-200
