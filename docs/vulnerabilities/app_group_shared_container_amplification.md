# App Group Shared-Container Privilege Amplification

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `app_group_shared_container_amplification` |
| Category | `system_provider` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M9 |
| MASVS | MASVS-STORAGE-1, MASVS-PLATFORM-1 |
| MASWE | MASWE-0002 |
| MASTG (v2 tests) | MASTG-TEST-0388 |
| CWE | CWE-200, CWE-732, CWE-668 |
| Suggested tools | frida, objection, idb, plutil |

## Description

The app stores secrets (tokens, credentials, keys) in an App Group shared container / shared UserDefaults that every member of the group can read/write with no per-item access control, so a less-trusted extension (or an over-broadly-scoped sibling) reads or tampers with data it should never see. Shared-container membership amplifies privilege - 'App Group used' is not the finding, over-sharing is (Apple App Group shared-container class, OWASP MASTG-BEST-0068).

## Reproduce in the app

DVMA is the harness: open **App Group Shared-Container Privilege Amplification** (`app_group_shared_container_amplification`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- objection
- idb
- plutil

## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP MASVS: MASVS-STORAGE-1, MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0002
- OWASP MASTG (v2 tests): MASTG-TEST-0388
- CWE: CWE-200, CWE-732, CWE-668
