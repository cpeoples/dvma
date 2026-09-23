# AI Output Used as Intent / URL (navigation & redirection)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `ai_output_to_intent_url` |
| Category | `ai_mobile` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP LLM/GenAI Top 10 (2025) | LLM05 |
| MASVS | MASVS-PLATFORM-1, MASVS-PLATFORM-3 |
| MASWE | MASWE-0032 |
| MASTG (v2 tests) | MASTG-TEST-0027, MASTG-TEST-0026 |
| MASTG demos | MASTG-DEMO-0095 |
| CWE | CWE-601, CWE-441, CWE-20 |
| Suggested tools | garak, promptfoo, frida |

## Description

The assistant's output is fed directly into startActivity()/url launcher, so a prompt-injected model can drive navigation, open redirects, or fire intents on the user's behalf without a confirmation boundary.

## Reproduce in the app

DVMA is the harness: open **AI Output Used as Intent / URL (navigation & redirection)** (`ai_output_to_intent_url`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- garak
- promptfoo
- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for LLM/GenAI Applications (2025): LLM05
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-PLATFORM-3
- OWASP MASWE: MASWE-0032
- OWASP MASTG (v2 tests): MASTG-TEST-0027, MASTG-TEST-0026
- OWASP MASTG demos: MASTG-DEMO-0095
- CWE: CWE-601, CWE-441, CWE-20
