# Passkey Assertion Replay (Sign-Count Not Enforced)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `passkey_assertion_replay_signcount` |
| Category | `auth` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-2 |
| MASWE | MASWE-0020 |
| CWE | CWE-294, CWE-304 |
| Suggested tools | webauthn test harness, mitmproxy, Burp Suite |

## Description

The authenticator sign-count / credential counter is never persisted or compared, so a captured WebAuthn assertion replays to create additional authenticated sessions (Craft CMS CVE-2026-72780 class).

## Reproduce in the app

DVMA is the harness: open **Passkey Assertion Replay (Sign-Count Not Enforced)** (`passkey_assertion_replay_signcount`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- webauthn test harness
- mitmproxy
- Burp Suite

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-2
- OWASP MASWE: MASWE-0020
- CWE: CWE-294, CWE-304
