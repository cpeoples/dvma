# Hidden Context Exposure

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `hidden_context_exposure` |
| Category | `ai_ml` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP LLM/GenAI Top 10 (2025) | LLM07 |
| MASVS | MASVS-STORAGE-2 |
| MASWE | MASWE-0002 |
| CWE | CWE-200, CWE-668 |
| Suggested tools | garak, promptfoo |

## Description

Untrusted retrieved/tool context that should have stayed out of reach (secrets, other users' data) is exposed to the model and the user (successor to system-prompt leakage).

## Reproduce in the app

DVMA is the harness: open **Hidden Context Exposure** (`hidden_context_exposure`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- garak
- promptfoo

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for LLM/GenAI Applications (2025): LLM07
- OWASP MASVS: MASVS-STORAGE-2
- OWASP MASWE: MASWE-0002
- CWE: CWE-200, CWE-668
