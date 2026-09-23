# Agent Task-Recovery Loop Weaponization

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `agent_recovery_loop_weaponization` |
| Category | `agentic` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP Agentic AI Top 10 (2025) | ASI03 |
| MASVS | MASVS-CODE-4 |
| MASWE | MASWE-0050 |
| CWE | CWE-693, CWE-441 |
| Suggested tools | promptfoo |

## Description

The agent's own error/task-recovery logic ("if stuck, tap back and retry") is steered by attacker-planted on-screen hints into a programmable multi-step exploit loop, turning resilience logic into an attack primitive.

## Reproduce in the app

DVMA is the harness: open **Agent Task-Recovery Loop Weaponization** (`agent_recovery_loop_weaponization`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- promptfoo

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for Agentic AI Applications (2025): ASI03
- OWASP MASVS: MASVS-CODE-4
- OWASP MASWE: MASWE-0050
- CWE: CWE-693, CWE-441
