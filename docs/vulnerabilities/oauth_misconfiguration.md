# OAuth Misconfiguration (implicit flow token leakage)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `oauth_misconfiguration` |
| Category | `auth` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-1 |
| MASWE | MASWE-0018 |
| CWE | CWE-598, CWE-200 |
| Suggested tools | mitmproxy, Burp Suite |

## Description

Implicit-flow access token leaks via redirect URL and logs.

## Reproduce in the app

DVMA is the harness: open **OAuth Misconfiguration (implicit flow token leakage)** (`oauth_misconfiguration`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- Burp Suite

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-1
- OWASP MASWE: MASWE-0018
- CWE: CWE-598, CWE-200
