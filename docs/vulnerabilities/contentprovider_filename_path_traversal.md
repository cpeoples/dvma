# ContentProvider File-Import Filename Path Traversal

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `contentprovider_filename_path_traversal` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-STORAGE-2 |
| MASWE | MASWE-0032, MASWE-0050 |
| MASTG (v2 tests) | MASTG-TEST-0357 |
| MASTG demos | MASTG-DEMO-0139, MASTG-DEMO-0141 |
| CWE | CWE-22, CWE-73, CWE-926 |
| Suggested tools | adb, drozer, jadx |

## Description

A ContentProvider / file-import API takes the caller-supplied display name / filename and writes or reads it under the app's storage with no canonicalization, so a `../` filename traverses out of the intended directory and overwrites/reads arbitrary app files (Android ContentProvider import traversal CVE-2025-65814 / CVE-2025-65815 class).

## Reproduce in the app

DVMA is the harness: open **ContentProvider File-Import Filename Path Traversal** (`contentprovider_filename_path_traversal`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-STORAGE-2
- OWASP MASWE: MASWE-0032, MASWE-0050
- OWASP MASTG (v2 tests): MASTG-TEST-0357
- OWASP MASTG demos: MASTG-DEMO-0139, MASTG-DEMO-0141
- CWE: CWE-22, CWE-73, CWE-926
