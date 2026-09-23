# Insecure Randomness (predictable tokens/session IDs)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `insecure_random` |
| Category | `crypto` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M10 |
| MASVS | MASVS-CRYPTO-1 |
| MASWE | MASWE-0012 |
| MASTG (v2 tests) | MASTG-TEST-0204, MASTG-TEST-0205, MASTG-TEST-0311, MASTG-TEST-0349 |
| MASTG demos | MASTG-DEMO-0007, MASTG-DEMO-0008 |
| CWE | CWE-330, CWE-338 |
| Suggested tools | frida, frida-trace, token analysis |

## Description

Uses Random() instead of Random.secure() for tokens/session IDs.

## Reproduce in the app

DVMA is the harness: open **Insecure Randomness (predictable tokens/session IDs)** (`insecure_random`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- frida-trace
- token analysis

## Standards mapping

- OWASP Mobile Top 10 (2024): M10
- OWASP MASVS: MASVS-CRYPTO-1
- OWASP MASWE: MASWE-0012
- OWASP MASTG (v2 tests): MASTG-TEST-0204, MASTG-TEST-0205, MASTG-TEST-0311, MASTG-TEST-0349
- OWASP MASTG demos: MASTG-DEMO-0007, MASTG-DEMO-0008
- CWE: CWE-330, CWE-338
