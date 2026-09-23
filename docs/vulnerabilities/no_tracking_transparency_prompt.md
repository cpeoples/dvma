# No Tracking Transparency Prompt

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `no_tracking_transparency_prompt` |
| Category | `privacy` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M6 |
| MASVS | MASVS-PRIVACY-3 |
| MASWE | MASWE-0074 |
| MASTG (v2 tests) | MASTG-TEST-0281 |
| CWE | CWE-359 |
| Suggested tools | mitmproxy |

## Description

Cross-app tracking begins with no ATT-equivalent prompt.

## Reproduce in the app

DVMA is the harness: open **No Tracking Transparency Prompt** (`no_tracking_transparency_prompt`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy

## Standards mapping

- OWASP Mobile Top 10 (2024): M6
- OWASP MASVS: MASVS-PRIVACY-3
- OWASP MASWE: MASWE-0074
- OWASP MASTG (v2 tests): MASTG-TEST-0281
- CWE: CWE-359
