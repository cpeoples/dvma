# AI Output -> Tool / Command Injection

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `ai_output_command_tool_injection` |
| Category | `ai_mobile` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP LLM/GenAI Top 10 (2025) | LLM06 |
| OWASP Agentic AI Top 10 (2025) | ASI03 |
| MASVS | MASVS-CODE-4, MASVS-AUTH-3 |
| MASWE | MASWE-0050 |
| CWE | CWE-77, CWE-88, CWE-862 |
| Suggested tools | garak, promptfoo, frida, objection |

## Description

The assistant maps model output to a tool/command invocation and executes it (with the app's privileges) before any validation, so attacker-influenced output triggers privileged operations (Microsoft 365 Copilot iOS/Android CVE-2026-26133 command-injection class).

## Reproduce in the app

DVMA is the harness: open **AI Output -> Tool / Command Injection** (`ai_output_command_tool_injection`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- garak
- promptfoo
- frida
- objection

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for LLM/GenAI Applications (2025): LLM06
- OWASP Top 10 for Agentic AI Applications (2025): ASI03
- OWASP MASVS: MASVS-CODE-4, MASVS-AUTH-3
- OWASP MASWE: MASWE-0050
- CWE: CWE-77, CWE-88, CWE-862
