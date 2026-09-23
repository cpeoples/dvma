# Unbounded AI Resource Consumption

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `unbounded_ai_resource_consumption` |
| Category | `ai_ml` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP LLM/GenAI Top 10 (2025) | LLM04 |
| MASVS | MASVS-CODE-4 |
| MASWE | MASWE-0050 |
| CWE | CWE-770, CWE-400 |
| Suggested tools | Burp Suite, mitmproxy |

## Description

No rate limiting on AI calls enables a cost-exhaustion attack.

## Reproduce in the app

DVMA is the harness: open **Unbounded AI Resource Consumption** (`unbounded_ai_resource_consumption`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- Burp Suite
- mitmproxy

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for LLM/GenAI Applications (2025): LLM04
- OWASP MASVS: MASVS-CODE-4
- OWASP MASWE: MASWE-0050
- CWE: CWE-770, CWE-400
