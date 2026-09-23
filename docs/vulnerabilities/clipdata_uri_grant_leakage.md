# ClipData URI-Grant Leakage

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `clipdata_uri_grant_leakage` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-STORAGE-2 |
| MASWE | MASWE-0032 |
| MASTG (v2 tests) | MASTG-TEST-0357 |
| MASTG demos | MASTG-DEMO-0123 |
| CWE | CWE-200, CWE-668, CWE-927 |
| Suggested tools | adb, drozer, jadx |

## Description

The app attaches a private `content://` URI to an Intent's `ClipData` (or copies it) together with `FLAG_GRANT_READ_URI_PERMISSION` and fires it to an implicit / untrusted target, unintentionally FORWARDING a read capability for its own provider data to another app. The grant rides silently on the ClipData rather than the data URI. Distinct from clipboard text theft: this leaks a capability, not a value. The secure path sends explicit intents to a pinned package and never grants on ClipData bound for untrusted resolvers (Android ClipData-grant class).

## Reproduce in the app

DVMA is the harness: open **ClipData URI-Grant Leakage** (`clipdata_uri_grant_leakage`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

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
- CWE: CWE-200, CWE-668, CWE-927
