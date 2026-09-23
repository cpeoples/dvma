# MCP open_url -> Arbitrary Android Intent

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `mcp_open_url_arbitrary_intent` |
| Category | `agentic` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP LLM/GenAI Top 10 (2025) | LLM01 |
| OWASP Agentic AI Top 10 (2025) | ASI03 |
| MASVS | MASVS-PLATFORM-1, MASVS-CODE-4 |
| MASWE | MASWE-0032 |
| MASTG (v2 tests) | MASTG-TEST-0026, MASTG-TEST-0027 |
| CWE | CWE-77, CWE-939, CWE-862 |
| Suggested tools | promptfoo, Burp Suite, MCP scanner, mitmproxy |

## Description

An MCP tool the agent can invoke (mobile_open_url) maps a model-supplied URL straight to Android startActivity() with no scheme allowlist, so a prompt-injected agent fires dangerous intents (tel:/sms:/content://) and reaches privileged, cross-app actions (Mobile MCP CVE-2026-35394 class).

## Reproduce in the app

DVMA is the harness: open **MCP open_url -> Arbitrary Android Intent** (`mcp_open_url_arbitrary_intent`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- promptfoo
- Burp Suite
- MCP scanner
- mitmproxy

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for LLM/GenAI Applications (2025): LLM01
- OWASP Top 10 for Agentic AI Applications (2025): ASI03
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-CODE-4
- OWASP MASWE: MASWE-0032
- OWASP MASTG (v2 tests): MASTG-TEST-0026, MASTG-TEST-0027
- CWE: CWE-77, CWE-939, CWE-862
