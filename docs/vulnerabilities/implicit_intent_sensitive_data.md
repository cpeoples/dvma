# Implicit Intent Leaks Sensitive Data

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `implicit_intent_sensitive_data` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-STORAGE-2 |
| MASWE | MASWE-0032 |
| MASTG (v2 tests) | MASTG-TEST-0374, MASTG-TEST-0372 |
| MASTG demos | MASTG-DEMO-0138 |
| CWE | CWE-927, CWE-200 |
| Suggested tools | adb, drozer, jadx |

## Description

Sensitive data is placed on an implicit intent (no explicit component/package), so any co-resident app registering a matching filter receives it (Samsung Smart View CVE-2025-21024 class).

## Reproduce in the app

DVMA is the harness: open **Implicit Intent Leaks Sensitive Data** (`implicit_intent_sensitive_data`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-STORAGE-2
- OWASP MASWE: MASWE-0032
- OWASP MASTG (v2 tests): MASTG-TEST-0374, MASTG-TEST-0372
- OWASP MASTG demos: MASTG-DEMO-0138
- CWE: CWE-927, CWE-200
