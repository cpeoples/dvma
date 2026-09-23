# Backup Archive Integrity Tampering

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `backup_archive_integrity_tampering` |
| Category | `storage` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M9 |
| MASVS | MASVS-STORAGE-2, MASVS-RESILIENCE-3 |
| MASWE | MASWE-0006 |
| MASTG (v2 tests) | MASTG-TEST-0338, MASTG-TEST-0387 |
| MASTG demos | MASTG-DEMO-0101, MASTG-DEMO-0150 |
| CWE | CWE-345, CWE-565, CWE-494 |
| Suggested tools | sqlite3, xxd |

## Description

The app does not verify the INTEGRITY of a backup archive before restoring it, so an attacker extracts a backup, edits persisted state (entitlements, balances, feature flags, an is_premium/is_admin bit), re-packs it, and restores - and the app trusts the attacker-controlled state. This is the integrity direction of backups (not the read/leak direction): the restore path is the boundary (unsigned-backup tampering CVE-2025-49199 class, OWASP MASTG-BEST-0065).

## Reproduce in the app

DVMA is the harness: open **Backup Archive Integrity Tampering** (`backup_archive_integrity_tampering`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- sqlite3
- xxd

## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP MASVS: MASVS-STORAGE-2, MASVS-RESILIENCE-3
- OWASP MASWE: MASWE-0006
- OWASP MASTG (v2 tests): MASTG-TEST-0338, MASTG-TEST-0387
- OWASP MASTG demos: MASTG-DEMO-0101, MASTG-DEMO-0150
- CWE: CWE-345, CWE-565, CWE-494
