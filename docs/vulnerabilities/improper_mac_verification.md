# Improper MAC Verification (non-constant-time / unauthenticated)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `improper_mac_verification` |
| Category | `crypto` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M10 |
| MASVS | MASVS-CRYPTO-1 |
| MASWE | MASWE-0009 |
| CWE | CWE-347, CWE-208 |
| Suggested tools | frida, frida-trace, r2 |

## Description

A signed token's HMAC is verified with a short-circuiting string equals (==) instead of a constant-time compare, leaking a timing oracle; a companion path skips MAC verification entirely and trusts the payload, so a forged tag is accepted.

## Reproduce in the app

DVMA is the harness: open **Improper MAC Verification (non-constant-time / unauthenticated)** (`improper_mac_verification`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- frida-trace
- r2

## Standards mapping

- OWASP Mobile Top 10 (2024): M10
- OWASP MASVS: MASVS-CRYPTO-1
- OWASP MASWE: MASWE-0009
- CWE: CWE-347, CWE-208
