# PendingIntent Provenance Confusion

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `pendingintent_provenance_confusion` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-AUTH-1 |
| MASWE | MASWE-0032, MASWE-0018 |
| MASTG (v2 tests) | MASTG-TEST-0381 |
| MASTG demos | MASTG-DEMO-0147 |
| CWE | CWE-441, CWE-290, CWE-923 |
| Suggested tools | adb, drozer, jadx |

## Description

An SDK/receiver assumes 'who presents a PendingIntent' == 'who created it', so a replayed/forwarded PendingIntent authenticates an attacker as the creating app (PendingIntent provenance-confusion research, arXiv 2603.02539).

## Reproduce in the app

DVMA is the harness: open **PendingIntent Provenance Confusion** (`pendingintent_provenance_confusion`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-AUTH-1
- OWASP MASWE: MASWE-0032, MASWE-0018
- OWASP MASTG (v2 tests): MASTG-TEST-0381
- OWASP MASTG demos: MASTG-DEMO-0147
- CWE: CWE-441, CWE-290, CWE-923
