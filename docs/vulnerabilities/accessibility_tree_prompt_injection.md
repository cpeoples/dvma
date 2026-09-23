# Accessibility Tree -> Indirect Prompt Injection

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `accessibility_tree_prompt_injection` |
| Category | `ai_mobile` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP LLM/GenAI Top 10 (2025) | LLM01 |
| MASVS | MASVS-PLATFORM-1, MASVS-CODE-4 |
| MASWE | MASWE-0040 |
| CWE | CWE-77, CWE-20, CWE-441 |
| Suggested tools | garak, promptfoo, accessibility inspector |

## Description

An on-device AI agent perceives the screen through the Android accessibility tree / visible UI text and feeds it into its prompt unfiltered, so untrusted app/UI content becomes an indirect prompt-injection channel that redirects the autonomous agent to unauthorized actions (Android Accessibility mobile-agent injection research).

## Reproduce in the app

DVMA is the harness: open **Accessibility Tree -> Indirect Prompt Injection** (`accessibility_tree_prompt_injection`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- garak
- promptfoo
- accessibility inspector

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for LLM/GenAI Applications (2025): LLM01
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-CODE-4
- OWASP MASWE: MASWE-0040
- CWE: CWE-77, CWE-20, CWE-441
