# Untrusted Mobile Input -> LLM Prompt (deep link / clipboard / QR)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `untrusted_mobile_input_to_llm` |
| Category | `ai_mobile` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP LLM/GenAI Top 10 (2025) | LLM01 |
| MASVS | MASVS-PLATFORM-3, MASVS-CODE-4 |
| MASWE | MASWE-0050 |
| CWE | CWE-77, CWE-20 |
| Suggested tools | garak, promptfoo |

## Description

Content arriving over a mobile trust boundary (deep-link param, clipboard, scanned QR, notification) is concatenated straight into the assistant's prompt, turning classic mobile IPC into a prompt-injection delivery channel (Monica CVE-2024-48142 class).

## Reproduce in the app

DVMA is the harness: open **Untrusted Mobile Input -> LLM Prompt (deep link / clipboard / QR)** (`untrusted_mobile_input_to_llm`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- garak
- promptfoo

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for LLM/GenAI Applications (2025): LLM01
- OWASP MASVS: MASVS-PLATFORM-3, MASVS-CODE-4
- OWASP MASWE: MASWE-0050
- CWE: CWE-77, CWE-20
