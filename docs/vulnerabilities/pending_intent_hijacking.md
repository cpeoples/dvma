# Pending Intent Hijacking

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `pending_intent_hijacking` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1 |
| MASWE | MASWE-0032 |
| MASTG (v2 tests) | MASTG-TEST-0381, MASTG-TEST-0030 |
| MASTG demos | MASTG-DEMO-0147 |
| CWE | CWE-927 |
| Suggested tools | adb, drozer, jadx, dumpsys |

## Description

Mutable, implicit PendingIntent can be intercepted/redirected.

## Reproduce in the app

DVMA is the harness: open **Pending Intent Hijacking** (`pending_intent_hijacking`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx
- dumpsys

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0032
- OWASP MASTG (v2 tests): MASTG-TEST-0381, MASTG-TEST-0030
- OWASP MASTG demos: MASTG-DEMO-0147
- CWE: CWE-927
