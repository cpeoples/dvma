# Cross-Profile (Work/Personal) Data & Capability Leakage

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `cross_profile_data_capability_leakage` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-STORAGE-1 |
| MASWE | MASWE-0032 |
| CWE | CWE-200, CWE-668, CWE-863 |
| Suggested tools | adb, drozer, jadx |

## Description

Managed (work) and primary (personal) profiles are a security boundary, but the app crosses it unsafely - forwarded intents, URI grants, shared files, notifications, clipboard, contacts, or account data move between profiles without the required affordance/authorization, so work data leaks to a personal surface (or vice-versa). This is a tenant-boundary violation on top of Android's cross-profile intent-forwarding machinery, distinct from ordinary intent redirection (Android managed-profile cross-profile leakage class).

## Reproduce in the app

DVMA is the harness: open **Cross-Profile (Work/Personal) Data & Capability Leakage** (`cross_profile_data_capability_leakage`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-STORAGE-1
- OWASP MASWE: MASWE-0032
- CWE: CWE-200, CWE-668, CWE-863
