# Insecure On-Device Model Storage

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `insecure_ondevice_model_storage` |
| Category | `ai_ml` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M9 |
| OWASP LLM/GenAI Top 10 (2025) | LLM03 |
| MASVS | MASVS-STORAGE-1, MASVS-RESILIENCE-3 |
| MASWE | MASWE-0001 |
| MASTG (v2 tests) | MASTG-TEST-0302, MASTG-TEST-0300 |
| CWE | CWE-312, CWE-353 |
| Suggested tools | r2, objection, frida, xxd |

## Description

On-device model file is unsigned/unencrypted and swappable.

## Reproduce in the app

DVMA is the harness: open **Insecure On-Device Model Storage** (`insecure_ondevice_model_storage`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- r2
- objection
- frida
- xxd

## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP Top 10 for LLM/GenAI Applications (2025): LLM03
- OWASP MASVS: MASVS-STORAGE-1, MASVS-RESILIENCE-3
- OWASP MASWE: MASWE-0001
- OWASP MASTG (v2 tests): MASTG-TEST-0302, MASTG-TEST-0300
- CWE: CWE-312, CWE-353
