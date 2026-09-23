# Agent Memory & Context Poisoning

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `agent_memory_poisoning` |
| Category | `agentic` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP LLM/GenAI Top 10 (2025) | LLM01 |
| OWASP Agentic AI Top 10 (2025) | ASI06 |
| MASVS | MASVS-CODE-4, MASVS-STORAGE-1 |
| MASWE | MASWE-0050 |
| CWE | CWE-349, CWE-77 |
| Suggested tools | promptfoo, garak, frida, sqlite3 |

## Description

A malicious instruction is written to the agent's persistent memory and re-fires across future sessions after the context resets (MINJA-style).

## Reproduce in the app

DVMA is the harness: open **Agent Memory & Context Poisoning** (`agent_memory_poisoning`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- promptfoo
- garak
- frida
- sqlite3

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for LLM/GenAI Applications (2025): LLM01
- OWASP Top 10 for Agentic AI Applications (2025): ASI06
- OWASP MASVS: MASVS-CODE-4, MASVS-STORAGE-1
- OWASP MASWE: MASWE-0050
- CWE: CWE-349, CWE-77
