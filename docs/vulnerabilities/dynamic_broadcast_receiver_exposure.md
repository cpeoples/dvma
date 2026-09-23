# Dynamic BroadcastReceiver Exposure

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `dynamic_broadcast_receiver_exposure` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1 |
| MASWE | MASWE-0032, MASWE-0018 |
| MASTG (v2 tests) | MASTG-TEST-0366 |
| MASTG demos | MASTG-DEMO-0130 |
| CWE | CWE-925, CWE-926, CWE-200 |
| Suggested tools | adb, drozer, jadx |

## Description

A runtime-registered receiver (`registerReceiver()` without `RECEIVER_NOT_EXPORTED` / a signature permission) is implicitly exported, so any co-resident app can send it a crafted broadcast to trigger sensitive functionality, or the app receives an untrusted broadcast and leaks data. Distinct from manifest-declared exported receivers: the dynamic registration flags are the boundary (Android MASTG-TEST-0366 class).

## Reproduce in the app

DVMA is the harness: open **Dynamic BroadcastReceiver Exposure** (`dynamic_broadcast_receiver_exposure`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0032, MASWE-0018
- OWASP MASTG (v2 tests): MASTG-TEST-0366
- OWASP MASTG demos: MASTG-DEMO-0130
- CWE: CWE-925, CWE-926, CWE-200
