# App Clip Invocation Injection

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `app_clip_invocation_injection` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-3, MASVS-AUTH-1 |
| MASWE | MASWE-0029, MASWE-0018 |
| CWE | CWE-20, CWE-862, CWE-501 |
| Suggested tools | ipsw, Hopper |

## Description

An App Clip acts on its invocation parameters (invocation URL / NFC / QR / associated-domain payload) - performing a purchase, order, or account action - while TRUSTING that the invocation came from a legitimate physical trigger and INHERITING authentication state as if it were the full app, so a crafted invocation URL drives a privileged action without the auth the full app would require. The invocation payload is attacker-controllable and must be treated as untrusted. The secure path validates the invocation against the associated domain, re-authenticates sensitive actions, and never inherits full-app trust (iOS App Clip class).

## Reproduce in the app

DVMA is the harness: open **App Clip Invocation Injection** (`app_clip_invocation_injection`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- ipsw
- Hopper

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-3, MASVS-AUTH-1
- OWASP MASWE: MASWE-0029, MASWE-0018
- CWE: CWE-20, CWE-862, CWE-501
