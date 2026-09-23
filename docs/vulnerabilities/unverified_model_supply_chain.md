# Unverified Model Supply Chain

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `unverified_model_supply_chain` |
| Category | `ai_ml` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M2 |
| OWASP LLM/GenAI Top 10 (2025) | LLM03 |
| MASVS | MASVS-NETWORK-1, MASVS-CODE-3 |
| MASWE | MASWE-0048 |
| MASTG (v2 tests) | MASTG-TEST-0233, MASTG-TEST-0338 |
| CWE | CWE-494, CWE-345 |
| Suggested tools | mitmproxy, Burp Suite |

## Description

Model update fetched from an unauthenticated URL with no checksum.

## Reproduce in the app

DVMA is the harness: open **Unverified Model Supply Chain** (`unverified_model_supply_chain`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- Burp Suite

## Standards mapping

- OWASP Mobile Top 10 (2024): M2
- OWASP Top 10 for LLM/GenAI Applications (2025): LLM03
- OWASP MASVS: MASVS-NETWORK-1, MASVS-CODE-3
- OWASP MASWE: MASWE-0048
- OWASP MASTG (v2 tests): MASTG-TEST-0233, MASTG-TEST-0338
- CWE: CWE-494, CWE-345
