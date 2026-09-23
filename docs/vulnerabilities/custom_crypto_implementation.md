# Custom / Homegrown Crypto

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `custom_crypto_implementation` |
| Category | `crypto` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M10 |
| MASVS | MASVS-CRYPTO-1 |
| MASWE | MASWE-0007 |
| MASTG (v2 tests) | MASTG-TEST-0210, MASTG-TEST-0221 |
| CWE | CWE-327 |
| Suggested tools | r2, r2ghidra, Ghidra, JEB, r2frida, frequency analysis |

## Description

A homegrown XOR-based 'encryption' scheme trivially reversible.

## Reproduce in the app

DVMA is the harness: open **Custom / Homegrown Crypto** (`custom_crypto_implementation`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- r2
- r2ghidra
- Ghidra
- JEB
- r2frida
- frequency analysis

## Standards mapping

- OWASP Mobile Top 10 (2024): M10
- OWASP MASVS: MASVS-CRYPTO-1
- OWASP MASWE: MASWE-0007
- OWASP MASTG (v2 tests): MASTG-TEST-0210, MASTG-TEST-0221
- CWE: CWE-327
