# Identity Credential / mDL Presentation Not Bound

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `identity_credential_presentation_binding` |
| Category | `auth` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-2, MASVS-AUTH-3 |
| MASWE | MASWE-0020 |
| CWE | CWE-345, CWE-384, CWE-290 |
| Suggested tools | mitmproxy |

## Description

A verifier accepts a digital-identity presentation (mDL/mDoc via Identity Credential / ISO 18013-5, or a Wallet identity assertion) without binding it to THIS session: it trusts caller-supplied holder metadata, skips the session-transcript / origin check, does not enforce user-presence, and confuses issuer identity with holder identity - so a replayed or relayed presentation from another session is accepted. Distinct from passkey/WebAuthn: this is the digital-ID / proximity-credential stack. The secure path verifies the issuer signature, binds the device-signed response to the session transcript + reader nonce, and requires fresh user presence.

## Reproduce in the app

DVMA is the harness: open **Identity Credential / mDL Presentation Not Bound** (`identity_credential_presentation_binding`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-2, MASVS-AUTH-3
- OWASP MASWE: MASWE-0020
- CWE: CWE-345, CWE-384, CWE-290
