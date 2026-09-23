# Passkey Registration/Deletion Authorization Missing

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `passkey_credential_management_authz` |
| Category | `auth` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-1, MASVS-AUTH-2 |
| MASWE | MASWE-0020 |
| CWE | CWE-862, CWE-639 |
| Suggested tools | webauthn test harness, Burp Suite, mitmproxy |

## Description

Passkey register/replace/delete endpoints don't re-authorize the acting user, so an attacker can add their own passkey or delete the victim's, causing account takeover or lockout (USENIX 2026 PASSKEYS-ATTACKER class).

## Reproduce in the app

DVMA is the harness: open **Passkey Registration/Deletion Authorization Missing** (`passkey_credential_management_authz`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- webauthn test harness
- Burp Suite
- mitmproxy

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-1, MASVS-AUTH-2
- OWASP MASWE: MASWE-0020
- CWE: CWE-862, CWE-639
