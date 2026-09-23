# Privacy Control Alternate-Path Bypass

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `privacy_control_alternate_path_bypass` |
| Category | `privacy` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M6 |
| MASVS | MASVS-PRIVACY-2, MASVS-PRIVACY-1 |
| MASWE | MASWE-0071 |
| CWE | CWE-284, CWE-668, CWE-200 |
| Suggested tools | frida, frida-trace |

## Description

App functionality reaches protected data through an ALTERNATE path that sidesteps the platform privacy control (a different API, a shared container / app group, an extension, a cached copy) instead of going through the gated, consent-checked path, so the user's privacy preference is bypassed rather than merely over-requested (iOS CVE-2026-20606 privacy-preference bypass class).

## Reproduce in the app

DVMA is the harness: open **Privacy Control Alternate-Path Bypass** (`privacy_control_alternate_path_bypass`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- frida-trace

## Standards mapping

- OWASP Mobile Top 10 (2024): M6
- OWASP MASVS: MASVS-PRIVACY-2, MASVS-PRIVACY-1
- OWASP MASWE: MASWE-0071
- CWE: CWE-284, CWE-668, CWE-200
