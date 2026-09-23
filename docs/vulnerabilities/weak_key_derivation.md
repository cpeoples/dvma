# Weak Key Derivation (no/low PBKDF2 iterations)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `weak_key_derivation` |
| Category | `crypto` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M10 |
| MASVS | MASVS-CRYPTO-1 |
| MASWE | MASWE-0014 |
| CWE | CWE-916, CWE-327 |
| Suggested tools | hashcat, frida, frida-trace |

## Description

Derives keys from passwords with missing or trivial KDF iteration counts.

## Reproduce in the app

DVMA is the harness: open **Weak Key Derivation (no/low PBKDF2 iterations)** (`weak_key_derivation`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- hashcat
- frida
- frida-trace

## Standards mapping

- OWASP Mobile Top 10 (2024): M10
- OWASP MASVS: MASVS-CRYPTO-1
- OWASP MASWE: MASWE-0014
- CWE: CWE-916, CWE-327
