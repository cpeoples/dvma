# Developer Backdoor

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `developer_backdoor` |
| Category | `auth` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-1, MASVS-CODE-2 |
| MASWE | MASWE-0018 |
| CWE | CWE-798, CWE-489, CWE-912 |
| Suggested tools | strings, r2, MobSF, JEB |

## Description

A hidden hardcoded backdoor credential / debug route grants privileged access.

## Reproduce in the app

DVMA is the harness: open **Developer Backdoor** (`developer_backdoor`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- strings
- r2
- MobSF
- JEB

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-1, MASVS-CODE-2
- OWASP MASWE: MASWE-0018
- CWE: CWE-798, CWE-489, CWE-912
