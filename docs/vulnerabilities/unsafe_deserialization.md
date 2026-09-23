# Unsafe Deserialization

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `unsafe_deserialization` |
| Category | `input_validation` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-CODE-4 |
| MASWE | MASWE-0050 |
| MASTG (v2 tests) | MASTG-TEST-0337, MASTG-TEST-0386 |
| MASTG demos | MASTG-DEMO-0100 |
| CWE | CWE-502 |
| Suggested tools | frida, r2frida |

## Description

Deserializes untrusted data into typed objects with no validation.

## Reproduce in the app

DVMA is the harness: open **Unsafe Deserialization** (`unsafe_deserialization`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- r2frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-CODE-4
- OWASP MASWE: MASWE-0050
- OWASP MASTG (v2 tests): MASTG-TEST-0337, MASTG-TEST-0386
- OWASP MASTG demos: MASTG-DEMO-0100
- CWE: CWE-502
