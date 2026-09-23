# FileProvider Path Traversal / Arbitrary File Sharing

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `fileprovider_path_traversal` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-STORAGE-1 |
| MASWE | MASWE-0032 |
| MASTG (v2 tests) | MASTG-TEST-0357 |
| MASTG demos | MASTG-DEMO-0122, MASTG-DEMO-0123 |
| CWE | CWE-22, CWE-926 |
| Suggested tools | adb, drozer, jadx |

## Description

An over-broad FileProvider / grantUriPermissions lets another app read arbitrary app-private files via a traversal path.

## Reproduce in the app

DVMA is the harness: open **FileProvider Path Traversal / Arbitrary File Sharing** (`fileprovider_path_traversal`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-STORAGE-1
- OWASP MASWE: MASWE-0032
- OWASP MASTG (v2 tests): MASTG-TEST-0357
- OWASP MASTG demos: MASTG-DEMO-0122, MASTG-DEMO-0123
- CWE: CWE-22, CWE-926
