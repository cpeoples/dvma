# Agent Tool Misuse / Confused Deputy

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `agent_tool_confused_deputy` |
| Category | `agentic` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP Agentic AI Top 10 (2025) | ASI03 |
| MASVS | MASVS-AUTH-3, MASVS-CODE-4 |
| MASWE | MASWE-0023 |
| CWE | CWE-441, CWE-862 |
| Suggested tools | promptfoo, Burp Suite, MCP scanner, mitmproxy, frida |

## Description

The agent reuses the app's own permissions/credentials to perform an unauthorized action on behalf of untrusted input (confused deputy).

## Reproduce in the app

DVMA is the harness: open **Agent Tool Misuse / Confused Deputy** (`agent_tool_confused_deputy`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- promptfoo
- Burp Suite
- MCP scanner
- mitmproxy
- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for Agentic AI Applications (2025): ASI03
- OWASP MASVS: MASVS-AUTH-3, MASVS-CODE-4
- OWASP MASWE: MASWE-0023
- CWE: CWE-441, CWE-862
