# Telephony / Phone-Account Capability Abuse

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `telephony_capability_abuse` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-AUTH-1 |
| MASWE | MASWE-0032, MASWE-0018 |
| MASTG (v2 tests) | MASTG-TEST-0365 |
| MASTG demos | MASTG-DEMO-0129 |
| CWE | CWE-862, CWE-284, CWE-441 |
| Suggested tools | adb, drozer, jadx |

## Description

A loosely-guarded / exported flow lets an untrusted caller drive a telephony capability - place a call, send an SMS, register or manipulate a phone account, redirect/intercept a call - via the Telecom component with no per-invocation permission check, so the app's real impact is far larger than its visible UI suggests (Android Telecom unauthorized-call permission-bypass CVE-2026-28615 class).

## Reproduce in the app

DVMA is the harness: open **Telephony / Phone-Account Capability Abuse** (`telephony_capability_abuse`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-AUTH-1
- OWASP MASWE: MASWE-0032, MASWE-0018
- OWASP MASTG (v2 tests): MASTG-TEST-0365
- OWASP MASTG demos: MASTG-DEMO-0129
- CWE: CWE-862, CWE-284, CWE-441
