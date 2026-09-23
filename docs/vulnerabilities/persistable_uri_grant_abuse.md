# Persistent URI-Grant Capability Abuse

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `persistable_uri_grant_abuse` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-STORAGE-2 |
| MASWE | MASWE-0032 |
| MASTG (v2 tests) | MASTG-TEST-0357 |
| MASTG demos | MASTG-DEMO-0123 |
| CWE | CWE-284, CWE-266, CWE-668 |
| Suggested tools | adb, drozer, jadx |

## Description

An exported component receives an attacker-controlled `content://` URI carrying `FLAG_GRANT_PERSISTABLE_URI_PERMISSION` and calls `takePersistableUriPermission()`, converting a one-shot, ephemeral grant into a LONG-LIVED capability the attacker's provider can later swap behind - so a transient read becomes durable, revocation-resistant access. Distinct from ordinary URI-grant abuse: the bug is the PERSISTENCE. The secure path never persists grants for untrusted URIs and re-validates the provider on each use (Android persistable-grant class).

## Reproduce in the app

DVMA is the harness: open **Persistent URI-Grant Capability Abuse** (`persistable_uri_grant_abuse`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

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
- CWE: CWE-284, CWE-266, CWE-668
