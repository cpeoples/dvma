# MCP Connector Capability Attestation Absent

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `mcp_capability_attestation_absent` |
| Category | `agentic` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP Agentic AI Top 10 (2025) | ASI04 |
| MASVS | MASVS-AUTH-3, MASVS-CODE-4 |
| MASWE | MASWE-0050 |
| CWE | CWE-290, CWE-862 |
| Suggested tools | promptfoo, MCP scanner, Burp Suite, mitmproxy |

## Description

A connected MCP server self-declares the capabilities (scopes) it holds, and the agent host grants them from the declaration alone with no attestation, so a connector that lists a privileged scope it was never issued is trusted with it (MCP capability-attestation gap, arXiv 2601.17549).

## Reproduce in the app

DVMA is the harness: open **MCP Connector Capability Attestation Absent** (`mcp_capability_attestation_absent`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- promptfoo
- MCP scanner
- Burp Suite
- mitmproxy

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for Agentic AI Applications (2025): ASI04
- OWASP MASVS: MASVS-AUTH-3, MASVS-CODE-4
- OWASP MASWE: MASWE-0050
- CWE: CWE-290, CWE-862
