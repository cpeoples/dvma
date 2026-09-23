# Universal Link / AASA Associated-Domain Confusion

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `universal_link_aasa_confusion` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-3, MASVS-CODE-4 |
| MASWE | MASWE-0029 |
| MASTG (v2 tests) | MASTG-TEST-0395, MASTG-TEST-0070 |
| MASTG demos | MASTG-DEMO-0153 |
| CWE | CWE-939, CWE-20, CWE-601 |
| Suggested tools | ipsw, Hopper |

## Description

The app trusts an incoming Universal Link because it matched an associated domain, but weak AASA deployment (overly broad path patterns / wildcards, open redirects on the domain, environment confusion between staging and prod, or a compromised/parked subdomain) lets an attacker craft a URL that routes to a sensitive in-app handler with attacker-controlled parameters. The whole app->associated-domain->AASA->web-server chain is the boundary, not just link parsing. The secure path uses tight AASA path matching, re-validates every parameter, and never treats a matched link as an authorization decision (iOS Universal-Link/AASA class).

## Reproduce in the app

DVMA is the harness: open **Universal Link / AASA Associated-Domain Confusion** (`universal_link_aasa_confusion`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- ipsw
- Hopper

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-3, MASVS-CODE-4
- OWASP MASWE: MASWE-0029
- OWASP MASTG (v2 tests): MASTG-TEST-0395, MASTG-TEST-0070
- OWASP MASTG demos: MASTG-DEMO-0153
- CWE: CWE-939, CWE-20, CWE-601
