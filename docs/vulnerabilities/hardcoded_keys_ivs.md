# Hardcoded Keys & Static IVs

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `hardcoded_keys_ivs` |
| Category | `crypto` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M10 |
| MASVS | MASVS-CRYPTO-1, MASVS-CRYPTO-2 |
| MASWE | MASWE-0004, MASWE-0007 |
| MASTG (v2 tests) | MASTG-TEST-0212, MASTG-TEST-0214, MASTG-TEST-0309, MASTG-TEST-0310 |
| MASTG demos | MASTG-DEMO-0017 |
| CWE | CWE-321, CWE-329 |
| Suggested tools | strings, frida, r2, MobSF, JEB |

## Description

Symmetric key and IV baked into the binary; IV reused across messages.

## Reproduce in the app

DVMA is the harness: open **Hardcoded Keys & Static IVs** (`hardcoded_keys_ivs`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- strings
- frida
- r2
- MobSF
- JEB

## Standards mapping

- OWASP Mobile Top 10 (2024): M10
- OWASP MASVS: MASVS-CRYPTO-1, MASVS-CRYPTO-2
- OWASP MASWE: MASWE-0004, MASWE-0007
- OWASP MASTG (v2 tests): MASTG-TEST-0212, MASTG-TEST-0214, MASTG-TEST-0309, MASTG-TEST-0310
- OWASP MASTG demos: MASTG-DEMO-0017
- CWE: CWE-321, CWE-329
