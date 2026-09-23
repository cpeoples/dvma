# Android Capability-Composition Chain

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `android_capability_composition_chain` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-AUTH-1 |
| MASWE | MASWE-0032, MASWE-0018 |
| CWE | CWE-441, CWE-862, CWE-668 |
| Suggested tools | adb, drozer, jadx, frida |

## Description

No single hop is the bug - the COMPOSITION is. A notification action carries a mutable `PendingIntent` -> it fires an exported BroadcastReceiver -> the receiver binds an exported Binder service -> the service performs a privileged transfer, and each hop trusts its predecessor instead of re-checking the original caller. An attacker who can trigger the notification action (or send the broadcast directly) laundered an untrusted request through four individually-benign links into a privileged operation. The secure path re-authorizes the ORIGINAL caller at the privileged sink and uses immutable/explicit intents + per-method authorization so the chain breaks at the first untrusted hop (capability-composition / confused-deputy chain).

## Reproduce in the app

DVMA is the harness: open **Android Capability-Composition Chain** (`android_capability_composition_chain`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx
- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-AUTH-1
- OWASP MASWE: MASWE-0032, MASWE-0018
- CWE: CWE-441, CWE-862, CWE-668
