# Privileged Input-Provider (IME) Event Injection

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `privileged_input_provider_injection` |
| Category | `system_provider` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-AUTH-1 |
| MASWE | MASWE-0018 |
| CWE | CWE-862, CWE-284, CWE-863 |
| Suggested tools | adb, drozer, jadx, frida |

## Description

The default input-method (IME) surface accepts key/motion events from an untrusted caller because a permission/caller check is missing, so a co-resident app injects synthetic input into other apps - typing, taps, confirmations - for local privilege escalation. This is the INJECT direction of the keyboard boundary (attacker drives the privileged IME), not the read/exposure direction (Android IME event-injection CVE-2025-26450 class).

## Reproduce in the app

DVMA is the harness: open **Privileged Input-Provider (IME) Event Injection** (`privileged_input_provider_injection`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx
- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-AUTH-1
- OWASP MASWE: MASWE-0018
- CWE: CWE-862, CWE-284, CWE-863
