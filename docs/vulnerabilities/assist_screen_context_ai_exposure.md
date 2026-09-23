# Assist / Screen-Context -> AI Action Exposure

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `assist_screen_context_ai_exposure` |
| Category | `system_provider` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M6 |
| MASVS | MASVS-PLATFORM-1, MASVS-PRIVACY-1 |
| MASWE | MASWE-0036 |
| CWE | CWE-200, CWE-668, CWE-863 |
| Suggested tools | adb, drozer, jadx, accessibility inspector, garak |

## Description

The app over-shares current-screen context through the Assist API (or fails to opt sensitive views out), so the system assistant / AI receives sensitive on-screen data; worse, untrusted UI text captured as screen context can steer the assistant into a privileged action (untrusted screen context -> AI -> action). The Assist/screen-context channel is a capability boundary distinct from accessibility (Android Assist screen-context exposure class).

## Reproduce in the app

DVMA is the harness: open **Assist / Screen-Context -> AI Action Exposure** (`assist_screen_context_ai_exposure`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx
- accessibility inspector
- garak

## Standards mapping

- OWASP Mobile Top 10 (2024): M6
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-PRIVACY-1
- OWASP MASWE: MASWE-0036
- CWE: CWE-200, CWE-668, CWE-863
