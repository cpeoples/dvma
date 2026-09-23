# Improper Signature Verification (payload not bound)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `improper_signature_verification` |
| Category | `crypto` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M10 |
| MASVS | MASVS-CRYPTO-1 |
| MASWE | MASWE-0011 |
| CWE | CWE-347 |
| Suggested tools | frida, r2, openssl |

## Description

An RSA-SHA256 signed update blob is accepted because the app only checks a signature is present and well-formed, never that it binds to the payload; an attacker keeps the original signature, swaps the payload, and the tampered update is accepted while a correct verification rejects it.

## Reproduce in the app

DVMA is the harness: open **Improper Signature Verification (payload not bound)** (`improper_signature_verification`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- r2
- openssl

## Standards mapping

- OWASP Mobile Top 10 (2024): M10
- OWASP MASVS: MASVS-CRYPTO-1
- OWASP MASWE: MASWE-0011
- CWE: CWE-347
