# Clipboard Leakage of Sensitive Fields

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `clipboard_leakage` |
| Category | `storage` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M9 |
| MASVS | MASVS-STORAGE-2 |
| MASWE | MASWE-0030 |
| MASTG (v2 tests) | MASTG-TEST-0276, MASTG-TEST-0277, MASTG-TEST-0278, MASTG-TEST-0279, MASTG-TEST-0280 |
| CWE | CWE-200 |
| Suggested tools | objection, frida |

## Description

Copies passwords/tokens to the global clipboard readable by any app.

## Reproduce in the app

DVMA is the harness: open **Clipboard Leakage of Sensitive Fields** (`clipboard_leakage`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- objection
- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP MASVS: MASVS-STORAGE-2
- OWASP MASWE: MASWE-0030
- OWASP MASTG (v2 tests): MASTG-TEST-0276, MASTG-TEST-0277, MASTG-TEST-0278, MASTG-TEST-0279, MASTG-TEST-0280
- CWE: CWE-200
