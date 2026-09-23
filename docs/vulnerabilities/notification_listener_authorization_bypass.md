# Notification Listener Authorization Bypass

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `notification_listener_authorization_bypass` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-AUTH-1 |
| MASWE | MASWE-0018 |
| CWE | CWE-862, CWE-284, CWE-306 |
| Suggested tools | adb, drozer, jadx |

## Description

Notification-listener access is effectively granted without a proper user grant - above the lock screen, or via an unverified NotificationListenerService intent filter - so a listener reads notification contents with no authorization / no user interaction (Android CVE-2025-22427 above-lock grant / CVE-2025-26442 intent-filter verification class).

## Reproduce in the app

DVMA is the harness: open **Notification Listener Authorization Bypass** (`notification_listener_authorization_bypass`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-AUTH-1
- OWASP MASWE: MASWE-0018
- CWE: CWE-862, CWE-284, CWE-306
