# Installed-App Enumeration (Privacy Fingerprint)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `installed_app_enumeration` |
| Category | `privacy` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M6 |
| MASVS | MASVS-PRIVACY-1, MASVS-PRIVACY-3 |
| MASWE | MASWE-0068 |
| MASTG (v2 tests) | MASTG-TEST-0255, MASTG-TEST-0024 |
| CWE | CWE-359, CWE-200 |
| Suggested tools | frida, frida-trace |

## Description

The app probes which OTHER apps are installed - iOS canOpenURL over a scheme list, Android queryIntentActivities / getInstalledPackages - with no functional need, building a device fingerprint and crossing a privacy boundary (iOS CVE-2026-20641 installed-apps disclosure class).

## Reproduce in the app

DVMA is the harness: open **Installed-App Enumeration (Privacy Fingerprint)** (`installed_app_enumeration`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- frida-trace

## Standards mapping

- OWASP Mobile Top 10 (2024): M6
- OWASP MASVS: MASVS-PRIVACY-1, MASVS-PRIVACY-3
- OWASP MASWE: MASWE-0068
- OWASP MASTG (v2 tests): MASTG-TEST-0255, MASTG-TEST-0024
- CWE: CWE-359, CWE-200
