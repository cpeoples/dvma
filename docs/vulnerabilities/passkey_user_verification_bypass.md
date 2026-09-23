# Passkey User-Verification (UV) Enforcement Bypass

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `passkey_user_verification_bypass` |
| Category | `auth` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-2 |
| MASWE | MASWE-0020 |
| CWE | CWE-287, CWE-306 |
| Suggested tools | webauthn test harness, mitmproxy, Burp Suite |

## Description

A configured userVerification=REQUIRED is silently not enforced, so assertions with the UV flag unset (presence-only) are accepted (Spring Security CVE-2026-47841 class).

## Reproduce in the app

DVMA is the harness: open **Passkey User-Verification (UV) Enforcement Bypass** (`passkey_user_verification_bypass`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- webauthn test harness
- mitmproxy
- Burp Suite

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-2
- OWASP MASWE: MASWE-0020
- CWE: CWE-287, CWE-306
