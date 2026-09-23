# MCP / Tool Description Poisoning

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `mcp_tool_poisoning` |
| Category | `agentic` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP Agentic AI Top 10 (2025) | ASI04 |
| MASVS | MASVS-CODE-4, MASVS-CODE-3 |
| MASWE | MASWE-0050 |
| CWE | CWE-829, CWE-77 |
| Suggested tools | promptfoo, Burp Suite, MCP scanner, mitmproxy |

## Description

A connected tool/MCP server's description carries hidden instructions that the agent ingests and obeys during planning.

## Reproduce in the app

DVMA is the harness: open **MCP / Tool Description Poisoning** (`mcp_tool_poisoning`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- promptfoo
- Burp Suite
- MCP scanner
- mitmproxy

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for Agentic AI Applications (2025): ASI04
- OWASP MASVS: MASVS-CODE-4, MASVS-CODE-3
- OWASP MASWE: MASWE-0050
- CWE: CWE-829, CWE-77
