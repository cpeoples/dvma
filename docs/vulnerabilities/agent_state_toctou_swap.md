# Agent External-State TOCTOU Swap

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `agent_state_toctou_swap` |
| Category | `agentic` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP Agentic AI Top 10 (2025) | ASI03 |
| MASVS | MASVS-CODE-4, MASVS-STORAGE-2 |
| MASWE | MASWE-0050 |
| CWE | CWE-367, CWE-345 |
| Suggested tools | promptfoo, frida |

## Description

The agent validates an external resource (a config file / API response) and then reads it again at use time; a swap between check and use makes it act on attacker-controlled state it never validated (TOCTOU in an LLM tool pipeline).

## Reproduce in the app

DVMA is the harness: open **Agent External-State TOCTOU Swap** (`agent_state_toctou_swap`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- promptfoo
- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for Agentic AI Applications (2025): ASI03
- OWASP MASVS: MASVS-CODE-4, MASVS-STORAGE-2
- OWASP MASWE: MASWE-0050
- CWE: CWE-367, CWE-345
