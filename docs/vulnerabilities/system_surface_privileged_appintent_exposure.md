# System-Surface -> Privileged App Intent Exposure

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `system_surface_privileged_appintent_exposure` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-3, MASVS-AUTH-1 |
| MASWE | MASWE-0018 |
| MASTG (v2 tests) | MASTG-TEST-0362 |
| MASTG demos | MASTG-DEMO-0127 |
| CWE | CWE-862, CWE-284, CWE-267 |
| Suggested tools | Siri |

## Description

An App Intent surfaced to many system entry points (Siri, Spotlight, Shortcuts, Widget, Control, Live Activity, Action Button, Apple Intelligence) reaches a privileged operation with no per-surface authorization, so ANY of those externally-invocable surfaces can trigger the action - the surface fan-out widens the attack surface far beyond the app UI (Apple App Intents multi-surface capability-exposure class).

## Reproduce in the app

DVMA is the harness: open **System-Surface -> Privileged App Intent Exposure** (`system_surface_privileged_appintent_exposure`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- Siri

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-3, MASVS-AUTH-1
- OWASP MASWE: MASWE-0018
- OWASP MASTG (v2 tests): MASTG-TEST-0362
- OWASP MASTG demos: MASTG-DEMO-0127
- CWE: CWE-862, CWE-284, CWE-267
