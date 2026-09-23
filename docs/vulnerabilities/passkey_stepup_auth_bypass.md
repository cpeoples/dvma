# Passkey Step-Up Authentication Bypass

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `passkey_stepup_auth_bypass` |
| Category | `auth` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-1, MASVS-AUTH-2 |
| MASWE | MASWE-0023 |
| CWE | CWE-287, CWE-863 |
| Suggested tools | webauthn test harness, mitmproxy, Burp Suite |

## Description

A sensitive action's 'step-up verified' flag is set from the mere existence of a registered passkey instead of a completed assertion, so step-up is satisfied without actually authenticating (New-API AI gateway CVE-2026-32879 class).

## Reproduce in the app

DVMA is the harness: open **Passkey Step-Up Authentication Bypass** (`passkey_stepup_auth_bypass`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- webauthn test harness
- mitmproxy
- Burp Suite

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-1, MASVS-AUTH-2
- OWASP MASWE: MASWE-0023
- CWE: CWE-287, CWE-863
