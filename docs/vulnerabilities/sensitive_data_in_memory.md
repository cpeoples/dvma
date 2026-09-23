# Sensitive Data in Memory

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `sensitive_data_in_memory` |
| Category | `storage` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M9 |
| MASVS | MASVS-STORAGE-1 |
| MASWE | MASWE-0001 |
| MASTG (v2 tests) | MASTG-TEST-0011, MASTG-TEST-0060 |
| CWE | CWE-316, CWE-226 |
| Suggested tools | objection, frida, r2frida |

## Description

Passwords/keys are held in long-lived, never-cleared objects, recoverable from a process memory dump.

## Reproduce in the app

DVMA is the harness: open **Sensitive Data in Memory** (`sensitive_data_in_memory`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- objection
- frida
- r2frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP MASVS: MASVS-STORAGE-1
- OWASP MASWE: MASWE-0001
- OWASP MASTG (v2 tests): MASTG-TEST-0011, MASTG-TEST-0060
- CWE: CWE-316, CWE-226
