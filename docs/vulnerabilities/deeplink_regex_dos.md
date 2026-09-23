# Deep Link Regex DoS (ReDoS)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `deeplink_regex_dos` |
| Category | `input_validation` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-CODE-4 |
| MASWE | MASWE-0050 |
| CWE | CWE-1333, CWE-400, CWE-20 |
| Suggested tools |  |

## Description

A catastrophically-backtracking regex parses incoming deep-link URLs, so a crafted link freezes/hangs the app (Mattermost CVE-2024-3872 class).

## Reproduce in the app

DVMA is the harness: open **Deep Link Regex DoS (ReDoS)** (`deeplink_regex_dos`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-CODE-4
- OWASP MASWE: MASWE-0050
- CWE: CWE-1333, CWE-400, CWE-20
