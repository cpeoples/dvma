# Direct Prompt Injection

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `prompt_injection_direct` |
| Category | `ai_ml` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP LLM/GenAI Top 10 (2025) | LLM01 |
| MASVS | MASVS-CODE-4 |
| MASWE | MASWE-0050 |
| CWE | CWE-77, CWE-20 |
| Suggested tools | garak, promptfoo |

## Description

User input can override the assistant's system instructions.

## Reproduce in the app

DVMA is the harness: open **Direct Prompt Injection** (`prompt_injection_direct`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- garak
- promptfoo

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for LLM/GenAI Applications (2025): LLM01
- OWASP MASVS: MASVS-CODE-4
- OWASP MASWE: MASWE-0050
- CWE: CWE-77, CWE-20
