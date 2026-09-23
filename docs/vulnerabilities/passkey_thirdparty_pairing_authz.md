# Third-Party Authenticator / Cross-Device Pairing Authorization Missing

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `passkey_thirdparty_pairing_authz` |
| Category | `auth` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-2, MASVS-PLATFORM-1 |
| MASWE | MASWE-0020 |
| CWE | CWE-862, CWE-306 |
| Suggested tools | webauthn test harness, mitmproxy |

## Description

Third-party authenticator / cross-device passkey-entry pairing is approved without a permission/authorization check, so an unauthorized app or device is paired for passkey entry (Android CVE-2025-48640 / BLE passkey-entry CVE-2026-65935 class).

## Reproduce in the app

DVMA is the harness: open **Third-Party Authenticator / Cross-Device Pairing Authorization Missing** (`passkey_thirdparty_pairing_authz`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- webauthn test harness
- mitmproxy

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-2, MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0020
- CWE: CWE-862, CWE-306
