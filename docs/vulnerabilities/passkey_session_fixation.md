# Session Fixation After WebAuthn Assertion

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `passkey_session_fixation` |
| Category | `auth` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-3, MASVS-AUTH-2 |
| MASWE | MASWE-0024 |
| CWE | CWE-384 |
| Suggested tools | webauthn test harness, Burp Suite, mitmproxy |

## Description

The session identifier is not rotated after a successful passkey assertion, so a pre-set (attacker-known) session id remains valid post-login (session fixation).

## Reproduce in the app

DVMA is the harness: open **Session Fixation After WebAuthn Assertion** (`passkey_session_fixation`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- webauthn test harness
- Burp Suite
- mitmproxy

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-3, MASVS-AUTH-2
- OWASP MASWE: MASWE-0024
- CWE: CWE-384
