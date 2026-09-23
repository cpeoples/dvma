# Zip Path Traversal (Zip-Slip)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `zip_path_traversal` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-CODE-4, MASVS-STORAGE-1 |
| MASWE | MASWE-0050 |
| CWE | CWE-22 |
| Suggested tools |  |

## Description

Update-package unpacker writes entries outside the target dir.

## Reproduce in the app

DVMA is the harness: open **Zip Path Traversal (Zip-Slip)** (`zip_path_traversal`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-CODE-4, MASVS-STORAGE-1
- OWASP MASWE: MASWE-0050
- CWE: CWE-22
