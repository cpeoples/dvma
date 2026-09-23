# RAG Vector Store Poisoning

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `rag_vector_store_poisoning` |
| Category | `ai_ml` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP LLM/GenAI Top 10 (2025) | LLM08 |
| MASVS | MASVS-CODE-4, MASVS-STORAGE-1 |
| MASWE | MASWE-0050 |
| CWE | CWE-349, CWE-345 |
| Suggested tools | promptfoo, objection, frida, sqlite3 |

## Description

A poisoned entry written to the on-device RAG/vector store is retrieved and trusted on later, unrelated queries.

## Reproduce in the app

DVMA is the harness: open **RAG Vector Store Poisoning** (`rag_vector_store_poisoning`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- promptfoo
- objection
- frida
- sqlite3

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for LLM/GenAI Applications (2025): LLM08
- OWASP MASVS: MASVS-CODE-4, MASVS-STORAGE-1
- OWASP MASWE: MASWE-0050
- CWE: CWE-349, CWE-345
