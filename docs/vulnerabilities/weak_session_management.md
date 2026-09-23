# Weak Session Management

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `weak_session_management` |
| Category | `auth` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-1, MASVS-AUTH-2 |
| MASWE | MASWE-0024 |
| CWE | CWE-613, CWE-330 |
| Suggested tools | mitmproxy, Burp Suite, token analysis |

## Description

Sessions never expire and use predictable, incrementing tokens.

## Reproduce in the app

DVMA is the harness: open **Weak Session Management** (`weak_session_management`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- Burp Suite
- token analysis

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-1, MASVS-AUTH-2
- OWASP MASWE: MASWE-0024
- CWE: CWE-613, CWE-330
