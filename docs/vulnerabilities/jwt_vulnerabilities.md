# JWT Vulnerabilities (alg:none, weak secret)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `jwt_vulnerabilities` |
| Category | `auth` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-2 |
| MASWE | MASWE-0020 |
| CWE | CWE-347, CWE-345 |
| Suggested tools | jwt_tool, hashcat, Burp Suite, mitmproxy |

## Description

Accepts alg:none tokens and verifies with a weak, guessable secret.

## Reproduce in the app

DVMA is the harness: open **JWT Vulnerabilities (alg:none, weak secret)** (`jwt_vulnerabilities`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- jwt_tool
- hashcat
- Burp Suite
- mitmproxy

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-2
- OWASP MASWE: MASWE-0020
- CWE: CWE-347, CWE-345
