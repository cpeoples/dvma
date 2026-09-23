# Silent SDK Auto-Update (Post-Deploy Behavior Change)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `silent_sdk_auto_update` |
| Category | `supply_chain` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M2 |
| MASVS | MASVS-CODE-3, MASVS-CODE-4 |
| MASWE | MASWE-0043 |
| CWE | CWE-494, CWE-829 |
| Suggested tools | jadx, apktool |

## Description

A benign-looking SDK silently fetches and swaps in new behavior at runtime (SpinOK-style), turning malicious after install with no app update or review.

## Reproduce in the app

DVMA is the harness: open **Silent SDK Auto-Update (Post-Deploy Behavior Change)** (`silent_sdk_auto_update`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- jadx
- apktool

## Standards mapping

- OWASP Mobile Top 10 (2024): M2
- OWASP MASVS: MASVS-CODE-3, MASVS-CODE-4
- OWASP MASWE: MASWE-0043
- CWE: CWE-494, CWE-829
