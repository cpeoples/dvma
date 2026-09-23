# Temp / Cache File Leftovers

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `temp_file_leftovers` |
| Category | `storage` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M9 |
| MASVS | MASVS-STORAGE-1 |
| MASWE | MASWE-0001 |
| MASTG (v2 tests) | MASTG-TEST-0207, MASTG-TEST-0299, MASTG-TEST-0302 |
| MASTG demos | MASTG-DEMO-0010 |
| CWE | CWE-459, CWE-312 |
| Suggested tools | objection |

## Description

Decrypted/sensitive content written to temp/cache dirs and never cleaned up.

## Reproduce in the app

DVMA is the harness: open **Temp / Cache File Leftovers** (`temp_file_leftovers`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- objection

## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP MASVS: MASVS-STORAGE-1
- OWASP MASWE: MASWE-0001
- OWASP MASTG (v2 tests): MASTG-TEST-0207, MASTG-TEST-0299, MASTG-TEST-0302
- OWASP MASTG demos: MASTG-DEMO-0010
- CWE: CWE-459, CWE-312
