# Privileged Provider Activation Abuse

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `privileged_provider_activation_abuse` |
| Category | `system_provider` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-AUTH-1 |
| MASWE | MASWE-0018 |
| CWE | CWE-1021, CWE-862, CWE-441 |
| Suggested tools | adb, drozer, jadx |

## Description

An app becomes an enabled system provider (accessibility / notification-listener / VPN / IME / device-admin / call-screening / phone-account / MediaProjection / credential-provider) through an enablement flow that can be coerced (tapjacked/overlaid into the toggle) and is not re-confirmed, then exposes a confused-deputy path so the granted capability is driven on an untrusted caller's behalf - the activation workflow is the security boundary (Android tapjack-to-enable phone-account CVE-2023-20913 class).

## Reproduce in the app

DVMA is the harness: open **Privileged Provider Activation Abuse** (`privileged_provider_activation_abuse`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-AUTH-1
- OWASP MASWE: MASWE-0018
- CWE: CWE-1021, CWE-862, CWE-441
