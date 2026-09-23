# Sensitive Notification -> Privileged AI Processing

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `notification_intelligence_ai_processing` |
| Category | `system_provider` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M6 |
| MASVS | MASVS-PLATFORM-1, MASVS-PRIVACY-1 |
| MASWE | MASWE-0037 |
| CWE | CWE-200, CWE-79, CWE-1230 |
| Suggested tools | adb, drozer, jadx, garak |

## Description

Sensitive notification content is fed to a privileged notification-intelligence / on-device AI consumer (summary, classification, smart-action) without redaction or trust separation, so attacker-controlled notification text becomes an indirect prompt-injection / exfiltration / action-injection channel into the AI - and can leak across apps. This is beyond a passive NotificationListener: the notification->AI pipeline is the new boundary (Android 16 notification-intelligence redaction class).

## Reproduce in the app

DVMA is the harness: open **Sensitive Notification -> Privileged AI Processing** (`notification_intelligence_ai_processing`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx
- garak

## Standards mapping

- OWASP Mobile Top 10 (2024): M6
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-PRIVACY-1
- OWASP MASWE: MASWE-0037
- CWE: CWE-200, CWE-79, CWE-1230
