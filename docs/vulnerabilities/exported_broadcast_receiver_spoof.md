# Exported BroadcastReceiver Data Spoofing

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `exported_broadcast_receiver_spoof` |
| Category | `native_bridge` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1 |
| MASWE | MASWE-0032 |
| MASTG (v2 tests) | MASTG-TEST-0366 |
| MASTG demos | MASTG-DEMO-0130 |
| CWE | CWE-925, CWE-862, CWE-346 |
| Suggested tools | adb, drozer, jadx |

## Description

An exported BroadcastReceiver accepts broadcasts from any app and trusts their extras, so a local app spoofs data the app treats as authoritative (e.g. device location) (Home Assistant Companion GHSA location-spoof class).

## Reproduce in the app

DVMA is the harness: open **Exported BroadcastReceiver Data Spoofing** (`exported_broadcast_receiver_spoof`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0032
- OWASP MASTG (v2 tests): MASTG-TEST-0366
- OWASP MASTG demos: MASTG-DEMO-0130
- CWE: CWE-925, CWE-862, CWE-346
