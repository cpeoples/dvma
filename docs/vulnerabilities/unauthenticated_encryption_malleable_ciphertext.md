# Unauthenticated Encryption (malleable ciphertext / bit-flipping)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `unauthenticated_encryption_malleable_ciphertext` |
| Category | `crypto` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M10 |
| MASVS | MASVS-CRYPTO-1, MASVS-CRYPTO-2 |
| MASWE | MASWE-0021 |
| CWE | CWE-353, CWE-326 |
| Suggested tools | frida, r2 |

## Description

A token is encrypted with AES-CBC and no MAC, so an attacker who never learns the key flips a ciphertext byte to predictably change the decrypted plaintext (bit-flipping); the secure path uses authenticated encryption (AES-GCM / encrypt-then-MAC) and rejects the tampered ciphertext.

## Reproduce in the app

DVMA is the harness: open **Unauthenticated Encryption (malleable ciphertext / bit-flipping)** (`unauthenticated_encryption_malleable_ciphertext`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- r2

## Standards mapping

- OWASP Mobile Top 10 (2024): M10
- OWASP MASVS: MASVS-CRYPTO-1, MASVS-CRYPTO-2
- OWASP MASWE: MASWE-0021
- CWE: CWE-353, CWE-326
