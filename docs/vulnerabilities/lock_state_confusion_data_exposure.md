# Lock-State Confusion Data Exposure

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `lock_state_confusion_data_exposure` |
| Category | `privacy` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M6 |
| MASVS | MASVS-PLATFORM-3, MASVS-PRIVACY-1 |
| MASWE | MASWE-0036 |
| MASTG (v2 tests) | MASTG-TEST-0246 |
| CWE | CWE-200, CWE-284, CWE-863 |
| Suggested tools |  |

## Description

Sensitive data or a privileged action is reachable while the device is LOCKED through an accessibility / notification / widget / VoiceOver path that never re-checks the keyguard, so the lock-screen boundary is bypassed and protected content is exposed on a locked device (iOS CVE-2026-20645 / CVE-2026-20661 lock-screen VoiceOver disclosure class).

## Reproduce in the app

DVMA is the harness: open **Lock-State Confusion Data Exposure** (`lock_state_confusion_data_exposure`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M6
- OWASP MASVS: MASVS-PLATFORM-3, MASVS-PRIVACY-1
- OWASP MASWE: MASWE-0036
- OWASP MASTG (v2 tests): MASTG-TEST-0246
- CWE: CWE-200, CWE-284, CWE-863
