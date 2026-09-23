# Ordered-Broadcast Result Injection

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `ordered_broadcast_result_injection` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1 |
| MASWE | MASWE-0032 |
| MASTG (v2 tests) | MASTG-TEST-0366 |
| MASTG demos | MASTG-DEMO-0130 |
| CWE | CWE-925, CWE-349, CWE-348 |
| Suggested tools | adb, drozer, jadx |

## Description

The app sends an ordered broadcast and then TRUSTS the aggregated `getResultData()` / result-extras, but a co-resident receiver registered at a higher priority runs first and calls `setResultData()` / `setResultExtras()` (or `abortBroadcast()`) to poison or suppress the result the app consumes for a security decision. The attacker sits in the middle of the app's own broadcast pipeline. The secure path never trusts ordered-broadcast results for security decisions and protects the broadcast with a signature permission (Android ordered-broadcast class).

## Reproduce in the app

DVMA is the harness: open **Ordered-Broadcast Result Injection** (`ordered_broadcast_result_injection`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0032
- OWASP MASTG (v2 tests): MASTG-TEST-0366
- OWASP MASTG demos: MASTG-DEMO-0130
- CWE: CWE-925, CWE-349, CWE-348
