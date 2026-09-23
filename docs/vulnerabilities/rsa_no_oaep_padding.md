# RSA Without OAEP Padding

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `rsa_no_oaep_padding` |
| Category | `crypto` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M10 |
| MASVS | MASVS-CRYPTO-1 |
| MASWE | MASWE-0022 |
| CWE | CWE-780, CWE-327 |
| Suggested tools | frida, openssl |

## Description

A payload is RSA-encrypted with legacy PKCS#1 v1.5 padding instead of OAEP, exposing it to Bleichenbacher-style chosen-ciphertext padding-oracle attacks; the secure path uses RSA-OAEP.

## Reproduce in the app

DVMA is the harness: open **RSA Without OAEP Padding** (`rsa_no_oaep_padding`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- openssl

## Standards mapping

- OWASP Mobile Top 10 (2024): M10
- OWASP MASVS: MASVS-CRYPTO-1
- OWASP MASWE: MASWE-0022
- CWE: CWE-780, CWE-327
