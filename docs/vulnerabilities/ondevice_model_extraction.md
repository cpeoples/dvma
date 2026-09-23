# On-Device Model Extraction / Theft

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `ondevice_model_extraction` |
| Category | `ai_ml` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M9 |
| OWASP LLM/GenAI Top 10 (2025) | LLM10 |
| MASVS | MASVS-STORAGE-1, MASVS-RESILIENCE-3 |
| MASWE | MASWE-0001 |
| MASTG (v2 tests) | MASTG-TEST-0302, MASTG-TEST-0300 |
| CWE | CWE-312, CWE-200 |
| Suggested tools | objection, r2, frida, xxd |

## Description

On-device model weights are readable/extractable from app storage, enabling model theft and offline attack crafting.

## Reproduce in the app

DVMA is the harness: open **On-Device Model Extraction / Theft** (`ondevice_model_extraction`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- objection
- r2
- frida
- xxd

## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP Top 10 for LLM/GenAI Applications (2025): LLM10
- OWASP MASVS: MASVS-STORAGE-1, MASVS-RESILIENCE-3
- OWASP MASWE: MASWE-0001
- OWASP MASTG (v2 tests): MASTG-TEST-0302, MASTG-TEST-0300
- CWE: CWE-312, CWE-200
