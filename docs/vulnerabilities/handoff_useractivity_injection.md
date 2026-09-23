# Handoff / NSUserActivity Injection

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `handoff_useractivity_injection` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-3, MASVS-CODE-4 |
| MASWE | MASWE-0050 |
| CWE | CWE-20, CWE-345, CWE-501 |
| Suggested tools | ipsw, Hopper, frida |

## Description

The receiving app restores state from a Handoff `NSUserActivity` (`userInfo` / `webpageURL`) and TRUSTS it - navigating, mutating state, or acting on an account/resource - without validating the source device, activity type, or account binding, so a crafted continuation payload drives the app to a privileged/attacker-chosen state. Handoff data is treated as trusted merely because it arrived over Continuity. The secure path validates activityType, binds the activity to the authenticated account, and treats userInfo/webpageURL as untrusted input (iOS Handoff class).

## Reproduce in the app

DVMA is the harness: open **Handoff / NSUserActivity Injection** (`handoff_useractivity_injection`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- ipsw
- Hopper
- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-3, MASVS-CODE-4
- OWASP MASWE: MASWE-0050
- CWE: CWE-20, CWE-345, CWE-501
