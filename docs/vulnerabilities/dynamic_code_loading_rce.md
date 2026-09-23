# Dynamic Code Loading (Arbitrary Code Execution)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `dynamic_code_loading_rce` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-CODE-4, MASVS-RESILIENCE-3 |
| MASWE | MASWE-0049 |
| CWE | CWE-494, CWE-829 |
| Suggested tools |  |

## Description

Loads and executes a dex/module/plugin from an untrusted third-party app or external storage with no verification.

## Reproduce in the app

DVMA is the harness: open **Dynamic Code Loading (Arbitrary Code Execution)** (`dynamic_code_loading_rce`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-CODE-4, MASVS-RESILIENCE-3
- OWASP MASWE: MASWE-0049
- CWE: CWE-494, CWE-829
