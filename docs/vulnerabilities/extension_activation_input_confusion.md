# App Extension Activation != Input Authorization

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `extension_activation_input_confusion` |
| Category | `system_provider` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-CODE-4 |
| MASWE | MASWE-0031 |
| MASTG (v2 tests) | MASTG-TEST-0072 |
| CWE | CWE-20, CWE-345, CWE-441 |
| Suggested tools | frida, objection, idb, Hopper |

## Description

An iOS app extension (Share / Action / File Provider / etc.) trusts the item it is handed simply because the system activated it - activation rules decide WHEN the extension is offered, not WHETHER the received NSItemProvider file/URL/text is safe. A crafted payload from any host app then drives a privileged extension operation. Extension activation != input authorization (Apple app-extension input-trust class, OWASP MASTG-TECH-0170).

## Reproduce in the app

DVMA is the harness: open **App Extension Activation != Input Authorization** (`extension_activation_input_confusion`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- objection
- idb
- Hopper

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-CODE-4
- OWASP MASWE: MASWE-0031
- OWASP MASTG (v2 tests): MASTG-TEST-0072
- CWE: CWE-20, CWE-345, CWE-441
