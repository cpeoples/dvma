# Insecure Inter-Agent Communication

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `insecure_inter_agent_comms` |
| Category | `agentic` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP Agentic AI Top 10 (2025) | ASI07 |
| MASVS | MASVS-CODE-4, MASVS-NETWORK-1 |
| MASWE | MASWE-0050 |
| CWE | CWE-345, CWE-290 |
| Suggested tools | promptfoo, Burp Suite, MCP scanner, mitmproxy |

## Description

Messages between sub-agents are unauthenticated, so a spoofed message misdirects the agent cluster.

## Reproduce in the app

DVMA is the harness: open **Insecure Inter-Agent Communication** (`insecure_inter_agent_comms`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- promptfoo
- Burp Suite
- MCP scanner
- mitmproxy

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for Agentic AI Applications (2025): ASI07
- OWASP MASVS: MASVS-CODE-4, MASVS-NETWORK-1
- OWASP MASWE: MASWE-0050
- CWE: CWE-345, CWE-290
