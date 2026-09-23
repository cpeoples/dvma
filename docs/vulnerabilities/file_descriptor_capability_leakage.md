# File-Descriptor Capability Leakage

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `file_descriptor_capability_leakage` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-STORAGE-2 |
| MASWE | MASWE-0032, MASWE-0018 |
| CWE | CWE-402, CWE-668, CWE-200 |
| Suggested tools | adb, drozer, frida, jadx |

## Description

The app passes an open `ParcelFileDescriptor` (via Binder, `openFile()`, or `detachFd()`) to an untrusted caller for a file/socket the caller could not otherwise open, handing over a live capability that bypasses path-based permission checks - the recipient inherits access to whatever the FD points at, including a sensitive DB or a privileged socket. Conceptually different from path traversal: an already-open capability is transferred. The secure path opens FDs read-only to a narrowly-scoped, non-sensitive resource and validates the caller before returning any descriptor (Android FD-passing class).

## Reproduce in the app

DVMA is the harness: open **File-Descriptor Capability Leakage** (`file_descriptor_capability_leakage`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- frida
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-STORAGE-2
- OWASP MASWE: MASWE-0032, MASWE-0018
- CWE: CWE-402, CWE-668, CWE-200
