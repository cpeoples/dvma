# Client-Side-Only Authorization

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `client_side_only_authorization` |
| Category | `auth` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-3 |
| MASWE | MASWE-0018 |
| CWE | CWE-602, CWE-639 |
| Suggested tools | frida, objection, r2frida |

## Description

Admin-only actions gated purely by a client-side boolean flag.

## Reproduce in the app

DVMA is the harness: open **Client-Side-Only Authorization** (`client_side_only_authorization`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- objection
- r2frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-3
- OWASP MASWE: MASWE-0018
- CWE: CWE-602, CWE-639
