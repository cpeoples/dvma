# JS Bridge Callback-ID Injection

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `js_bridge_callback_id_injection` |
| Category | `native_bridge` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-2, MASVS-CODE-4 |
| MASWE | MASWE-0033 |
| MASTG (v2 tests) | MASTG-TEST-0334 |
| MASTG demos | MASTG-DEMO-0097 |
| CWE | CWE-345, CWE-441, CWE-20 |
| Suggested tools | r2frida, objection, frida, mitmproxy |

## Description

The native bridge trusts a caller-supplied callbackId and dispatches the result to it without validation, so web content forges an id to invoke a native callback belonging to another (privileged) plugin - Camera/Contacts/Files/Geolocation (Cordova InAppBrowser iOS CVE-2026-47430 class).

## Reproduce in the app

DVMA is the harness: open **JS Bridge Callback-ID Injection** (`js_bridge_callback_id_injection`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- r2frida
- objection
- frida
- mitmproxy

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-2, MASVS-CODE-4
- OWASP MASWE: MASWE-0033
- OWASP MASTG (v2 tests): MASTG-TEST-0334
- OWASP MASTG demos: MASTG-DEMO-0097
- CWE: CWE-345, CWE-441, CWE-20
