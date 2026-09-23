# Hardcoded LLM API Keys

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `hardcoded_llm_api_keys` |
| Category | `ai_ml` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M1 |
| OWASP LLM/GenAI Top 10 (2025) | LLM10 |
| MASVS | MASVS-STORAGE-1, MASVS-CRYPTO-1 |
| MASWE | MASWE-0004 |
| MASTG (v2 tests) | MASTG-TEST-0212, MASTG-TEST-0214 |
| MASTG demos | MASTG-DEMO-0017 |
| CWE | CWE-798 |
| Suggested tools | strings, r2, MobSF |

## Description

A cloud-LLM API key is shipped in the binary.

## Reproduce in the app

DVMA is the harness: open **Hardcoded LLM API Keys** (`hardcoded_llm_api_keys`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- strings
- r2
- MobSF

## Standards mapping

- OWASP Mobile Top 10 (2024): M1
- OWASP Top 10 for LLM/GenAI Applications (2025): LLM10
- OWASP MASVS: MASVS-STORAGE-1, MASVS-CRYPTO-1
- OWASP MASWE: MASWE-0004
- OWASP MASTG (v2 tests): MASTG-TEST-0212, MASTG-TEST-0214
- OWASP MASTG demos: MASTG-DEMO-0017
- CWE: CWE-798
