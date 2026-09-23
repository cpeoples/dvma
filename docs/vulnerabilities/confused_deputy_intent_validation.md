# Confused-Deputy Intent Validation Bypass

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `confused_deputy_intent_validation` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-AUTH-1 |
| MASWE | MASWE-0032, MASWE-0018 |
| MASTG (v2 tests) | MASTG-TEST-0364 |
| MASTG demos | MASTG-DEMO-0128 |
| CWE | CWE-441, CWE-863, CWE-862 |
| Suggested tools | adb, drozer, jadx |

## Description

A privileged component performs an action on behalf of a caller after only a superficial Intent check, letting a local app abuse the app's privileges (Android Settings CVE-2025-32326 / CVE-2025-32321 confused-deputy class).

## Reproduce in the app

DVMA is the harness: open **Confused-Deputy Intent Validation Bypass** (`confused_deputy_intent_validation`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-AUTH-1
- OWASP MASWE: MASWE-0032, MASWE-0018
- OWASP MASTG (v2 tests): MASTG-TEST-0364
- OWASP MASTG demos: MASTG-DEMO-0128
- CWE: CWE-441, CWE-863, CWE-862
