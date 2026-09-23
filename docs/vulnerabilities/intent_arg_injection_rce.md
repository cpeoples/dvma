# Intent Argument Injection -> Local Code Execution

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `intent_arg_injection_rce` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-CODE-4 |
| MASWE | MASWE-0032 |
| CWE | CWE-88, CWE-829, CWE-94 |
| Suggested tools | adb, drozer, jadx, apktool |

## Description

An exported component feeds an attacker-controlled intent extra / command-line arg into an execution path, so another app runs code with this app's privileges (Unity CVE-2025-59489 class).

## Reproduce in the app

DVMA is the harness: open **Intent Argument Injection -> Local Code Execution** (`intent_arg_injection_rce`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx
- apktool

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-CODE-4
- OWASP MASWE: MASWE-0032
- CWE: CWE-88, CWE-829, CWE-94
