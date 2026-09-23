# Intent Redirection / Task Hijack (StrandHogg-style)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `intent_redirection` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1 |
| MASWE | MASWE-0032 |
| MASTG (v2 tests) | MASTG-TEST-0375 |
| CWE | CWE-926, CWE-940 |
| Suggested tools | adb, drozer, jadx |

## Description

An exported component forwards an attacker-supplied nested intent to an internal component (intent redirection), and lax task affinity enables task hijack.

## Reproduce in the app

DVMA is the harness: open **Intent Redirection / Task Hijack (StrandHogg-style)** (`intent_redirection`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0032
- OWASP MASTG (v2 tests): MASTG-TEST-0375
- CWE: CWE-926, CWE-940
