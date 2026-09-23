# Background Activity Launch Abuse

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `background_activity_launch_abuse` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-PLATFORM-3 |
| MASWE | MASWE-0032, MASWE-0039 |
| MASTG (v2 tests) | MASTG-TEST-0364 |
| MASTG demos | MASTG-DEMO-0128 |
| CWE | CWE-862, CWE-1021, CWE-284 |
| Suggested tools | adb, drozer, jadx |

## Description

An untrusted / local caller drives a background component to startActivity() reaching security-sensitive UI, so with no background-activity-launch restriction the app is coerced into phishing overlays, task hijacking, or consent-dialog manipulation on the user's behalf (Android background-activity-launch CVE-2025-26462 class).

## Reproduce in the app

DVMA is the harness: open **Background Activity Launch Abuse** (`background_activity_launch_abuse`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-PLATFORM-3
- OWASP MASWE: MASWE-0032, MASWE-0039
- OWASP MASTG (v2 tests): MASTG-TEST-0364
- OWASP MASTG demos: MASTG-DEMO-0128
- CWE: CWE-862, CWE-1021, CWE-284
