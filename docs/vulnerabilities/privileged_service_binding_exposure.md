# Privileged Service Binding / Binder Interface Exposure

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `privileged_service_binding_exposure` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-AUTH-1 |
| MASWE | MASWE-0018, MASWE-0032 |
| MASTG (v2 tests) | MASTG-TEST-0365 |
| MASTG demos | MASTG-DEMO-0129 |
| CWE | CWE-284, CWE-749, CWE-862 |
| Suggested tools | adb, drozer, jadx, frida |

## Description

An exported/bindable Service exposes a privileged Binder interface (AIDL/Messenger) that any app can `bindService()` to and call without a caller-identity / permission check, so an untrusted client invokes privileged operations or reads state established by another client. The binding model - not just 'service exported' - is the boundary (Android service IPC MASTG-KNOW-0133 class).

## Reproduce in the app

DVMA is the harness: open **Privileged Service Binding / Binder Interface Exposure** (`privileged_service_binding_exposure`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx
- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-AUTH-1
- OWASP MASWE: MASWE-0018, MASWE-0032
- OWASP MASTG (v2 tests): MASTG-TEST-0365
- OWASP MASTG demos: MASTG-DEMO-0129
- CWE: CWE-284, CWE-749, CWE-862
