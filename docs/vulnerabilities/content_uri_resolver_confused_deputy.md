# content:// URI -> ContentResolver Confused Deputy

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `content_uri_resolver_confused_deputy` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-AUTH-1 |
| MASWE | MASWE-0032, MASWE-0018 |
| MASTG (v2 tests) | MASTG-TEST-0355 |
| MASTG demos | MASTG-DEMO-0121 |
| CWE | CWE-441, CWE-862, CWE-639 |
| Suggested tools | adb, drozer, jadx |

## Description

The app takes an attacker-supplied content:// URI (e.g. from an intent extra) and reads it through its OWN ContentResolver, so it becomes a proxy for a privileged provider / file the caller cannot reach directly - a confused deputy with no owner/permission validation on the URI (Android DownloadProvider CVE-2025-26417 class).

## Reproduce in the app

DVMA is the harness: open **content:// URI -> ContentResolver Confused Deputy** (`content_uri_resolver_confused_deputy`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-AUTH-1
- OWASP MASWE: MASWE-0032, MASWE-0018
- OWASP MASTG (v2 tests): MASTG-TEST-0355
- OWASP MASTG demos: MASTG-DEMO-0121
- CWE: CWE-441, CWE-862, CWE-639
