# Credential Provider Release Authorization Failure

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `credential_provider_release_authorization` |
| Category | `auth` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-2, MASVS-AUTH-1 |
| MASWE | MASWE-0018 |
| CWE | CWE-863, CWE-284, CWE-346 |
| Suggested tools | frida, objection, r2frida |

## Description

A credential-provider / password-manager extension releases a stored credential or passkey assertion without validating the calling app / relying-party identity or the user-verification state, so a spoofed calling app or a relying-party mismatch obtains a credential (or enumerates entries) - the credential-release boundary, broader than WebAuthn itself (Apple/Android credential-provider extension authorization class).

## Reproduce in the app

DVMA is the harness: open **Credential Provider Release Authorization Failure** (`credential_provider_release_authorization`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- objection
- r2frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-2, MASVS-AUTH-1
- OWASP MASWE: MASWE-0018
- CWE: CWE-863, CWE-284, CWE-346
