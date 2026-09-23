# Content Provider SQL Injection

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `content_provider_sql_injection` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-CODE-4 |
| MASWE | MASWE-0018, MASWE-0050 |
| MASTG (v2 tests) | MASTG-TEST-0339, MASTG-TEST-0355 |
| MASTG demos | MASTG-DEMO-0102, MASTG-DEMO-0121 |
| CWE | CWE-89 |
| Suggested tools | adb, drozer, jadx, sqlite3 |

## Description

Exported content provider builds SQL by string concatenation.

## Reproduce in the app

DVMA is the harness: open **Content Provider SQL Injection** (`content_provider_sql_injection`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx
- sqlite3

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-CODE-4
- OWASP MASWE: MASWE-0018, MASWE-0050
- OWASP MASTG (v2 tests): MASTG-TEST-0339, MASTG-TEST-0355
- OWASP MASTG demos: MASTG-DEMO-0102, MASTG-DEMO-0121
- CWE: CWE-89
