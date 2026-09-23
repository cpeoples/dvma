# GUI Agent Action Rebinding (Observation-Action Gap)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `gui_agent_action_rebinding` |
| Category | `agentic` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP LLM/GenAI Top 10 (2025) | LLM01 |
| OWASP Agentic AI Top 10 (2025) | ASI03 |
| MASVS | MASVS-PLATFORM-1, MASVS-CODE-4 |
| MASWE | MASWE-0032 |
| CWE | CWE-367, CWE-441, CWE-862 |
| Suggested tools | promptfoo, frida |

## Description

A GUI agent plans a tap against the screen it observed, but a zero-permission app swaps the foreground to a sensitive target during the reasoning latency, so the planned action lands in a privileged context the agent never saw (cross-app Action Rebinding).

## Reproduce in the app

DVMA is the harness: open **GUI Agent Action Rebinding (Observation-Action Gap)** (`gui_agent_action_rebinding`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- promptfoo
- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for LLM/GenAI Applications (2025): LLM01
- OWASP Top 10 for Agentic AI Applications (2025): ASI03
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-CODE-4
- OWASP MASWE: MASWE-0032
- CWE: CWE-367, CWE-441, CWE-862
