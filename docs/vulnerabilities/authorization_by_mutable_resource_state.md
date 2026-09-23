# Authorization Based on Mutable Resource State

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `authorization_by_mutable_resource_state` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-AUTH-1 |
| MASWE | MASWE-0018 |
| CWE | CWE-367, CWE-708, CWE-863 |
| Suggested tools | adb, drozer, jadx |

## Description

A security/authorization decision is made on mutable resource existence or state (e.g. doesFileExist() -> grant access -> the file is then created/changed), so an app gains read/write to a resource - including files that do not yet exist - by racing or manipulating that state after the check (Android MediaProvider createRequest file-existence LPE CVE-2026-0035 class).

## Reproduce in the app

DVMA is the harness: open **Authorization Based on Mutable Resource State** (`authorization_by_mutable_resource_state`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-AUTH-1
- OWASP MASWE: MASWE-0018
- CWE: CWE-367, CWE-708, CWE-863
