# Shortcuts / App Intents Path + Symlink Sandbox Escape

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `shortcuts_path_symlink_sandbox_escape` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-STORAGE-2, MASVS-PLATFORM-3 |
| MASWE | MASWE-0050 |
| CWE | CWE-59, CWE-22, CWE-367 |
| Suggested tools | ifuse, afcclient |

## Description

Untrusted Shortcuts / App Intents input drives a file operation whose path is resolved through a symlink or a `../` traversal with no canonicalization, so the automation reaches files outside the app's sandbox / container and exposes sensitive user data (iOS Shortcuts CVE-2026-20677 symlink race / CVE-2026-20653 path class).

## Reproduce in the app

DVMA is the harness: open **Shortcuts / App Intents Path + Symlink Sandbox Escape** (`shortcuts_path_symlink_sandbox_escape`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- ifuse
- afcclient

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-STORAGE-2, MASVS-PLATFORM-3
- OWASP MASWE: MASWE-0050
- CWE: CWE-59, CWE-22, CWE-367
