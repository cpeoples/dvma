# Native Code Memory Bugs (JNI buffer overflow)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `native_code_memory_bugs` |
| Category | `code_quality` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M7 |
| MASVS | MASVS-CODE-4 |
| MASWE | MASWE-0050 |
| MASTG (v2 tests) | MASTG-TEST-0043, MASTG-TEST-0086 |
| CWE | CWE-120, CWE-787 |
| Suggested tools | r2, r2ghidra, Ghidra, JEB, frida, r2frida, IDA |

## Description

A small JNI/FFI routine with a classic unbounded copy (optional/high-effort).

## Reproduce in the app

DVMA is the harness: open **Native Code Memory Bugs (JNI buffer overflow)** (`native_code_memory_bugs`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- r2
- r2ghidra
- Ghidra
- JEB
- frida
- r2frida
- IDA

## Standards mapping

- OWASP Mobile Top 10 (2024): M7
- OWASP MASVS: MASVS-CODE-4
- OWASP MASWE: MASWE-0050
- OWASP MASTG (v2 tests): MASTG-TEST-0043, MASTG-TEST-0086
- CWE: CWE-120, CWE-787
