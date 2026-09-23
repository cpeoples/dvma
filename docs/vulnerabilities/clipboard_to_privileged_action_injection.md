# Clipboard -> Privileged Action Injection

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `clipboard_to_privileged_action_injection` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-2, MASVS-CODE-4 |
| MASWE | MASWE-0030 |
| CWE | CWE-20, CWE-77, CWE-441 |
| Suggested tools |  |

## Description

Clipboard content sourced from an untrusted origin flows into a privileged action (auto-paste into a payment/command field, an assistant/automation step) with no validation or origin check, so a malicious page-to-clipboard write is laundered into a privileged operation (webpage -> clipboard -> automation -> privileged app capability boundary; CVE-2026-17766 cross-origin clipboard class).

## Reproduce in the app

DVMA is the harness: open **Clipboard -> Privileged Action Injection** (`clipboard_to_privileged_action_injection`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-2, MASVS-CODE-4
- OWASP MASWE: MASWE-0030
- CWE: CWE-20, CWE-77, CWE-441
