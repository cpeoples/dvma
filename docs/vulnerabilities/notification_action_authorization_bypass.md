# Notification-Action / Trampoline Authorization Bypass

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `notification_action_authorization_bypass` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-AUTH-1, MASVS-PLATFORM-1 |
| MASWE | MASWE-0018, MASWE-0032 |
| MASTG (v2 tests) | MASTG-TEST-0381 |
| MASTG demos | MASTG-DEMO-0147 |
| CWE | CWE-862, CWE-306, CWE-863 |
| Suggested tools | adb, jadx |

## Description

A notification action fires a `PendingIntent` (or, on Android, trampolines through an exported receiver -> activity) that performs a privileged operation - approve transaction, unlock, delete, change account - WITHOUT a fresh authentication decision, because the intermediate component has weaker authorization semantics than the equivalent in-app UI flow. The action surface becomes an unauthenticated entry point into a sensitive operation. The secure path re-authenticates destructive actions and routes them through an authorization check regardless of entry surface (Android/iOS notification-action class).

## Reproduce in the app

DVMA is the harness: open **Notification-Action / Trampoline Authorization Bypass** (`notification_action_authorization_bypass`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-AUTH-1, MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0018, MASWE-0032
- OWASP MASTG (v2 tests): MASTG-TEST-0381
- OWASP MASTG demos: MASTG-DEMO-0147
- CWE: CWE-862, CWE-306, CWE-863
