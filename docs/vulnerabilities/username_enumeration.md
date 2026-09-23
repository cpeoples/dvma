# Username Enumeration

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `username_enumeration` |
| Category | `auth` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-1 |
| MASWE | MASWE-0018 |
| CWE | CWE-204, CWE-203 |
| Suggested tools | Burp Suite, mitmproxy |

## Description

Login returns distinguishable responses for valid vs invalid usernames, allowing account enumeration.

## Reproduce in the app

DVMA is the harness: open **Username Enumeration** (`username_enumeration`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- Burp Suite
- mitmproxy

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-1
- OWASP MASWE: MASWE-0018
- CWE: CWE-204, CWE-203
