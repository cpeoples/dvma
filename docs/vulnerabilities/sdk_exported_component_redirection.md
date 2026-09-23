# Bundled SDK Ships a Vulnerable Exported Component

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `sdk_exported_component_redirection` |
| Category | `supply_chain` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M2 |
| MASVS | MASVS-CODE-3, MASVS-PLATFORM-1 |
| MASWE | MASWE-0032 |
| MASTG (v2 tests) | MASTG-TEST-0364, MASTG-TEST-0372 |
| MASTG demos | MASTG-DEMO-0128, MASTG-DEMO-0136 |
| CWE | CWE-926, CWE-749, CWE-829 |
| Suggested tools |  |

## Description

A bundled third-party SDK ships its own vulnerable exported component that intent-redirects, so another app abuses the SDK (not the host app's code) to reach private data / credentials (EngageLab SDK, 50M+ installs).

## Reproduce in the app

DVMA is the harness: open **Bundled SDK Ships a Vulnerable Exported Component** (`sdk_exported_component_redirection`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M2
- OWASP MASVS: MASVS-CODE-3, MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0032
- OWASP MASTG (v2 tests): MASTG-TEST-0364, MASTG-TEST-0372
- OWASP MASTG demos: MASTG-DEMO-0128, MASTG-DEMO-0136
- CWE: CWE-926, CWE-749, CWE-829
