# URI Permission / GRANT_URI_PERMISSIONS Abuse

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `grant_uri_permission_abuse` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-STORAGE-2 |
| MASWE | MASWE-0032 |
| MASTG (v2 tests) | MASTG-TEST-0357 |
| MASTG demos | MASTG-DEMO-0123 |
| CWE | CWE-266, CWE-668, CWE-927 |
| Suggested tools | adb, drozer, jadx |

## Description

A forwarded/redirected Intent carries FLAG_GRANT_READ/WRITE_URI_PERMISSION to a private content:// URI, so a malicious app is transitively granted access to files it should not reach (Pixel CVE-2024-27222 Intent-redirect + grant-URI class).

## Reproduce in the app

DVMA is the harness: open **URI Permission / GRANT_URI_PERMISSIONS Abuse** (`grant_uri_permission_abuse`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-STORAGE-2
- OWASP MASWE: MASWE-0032
- OWASP MASTG (v2 tests): MASTG-TEST-0357
- OWASP MASTG demos: MASTG-DEMO-0123
- CWE: CWE-266, CWE-668, CWE-927
