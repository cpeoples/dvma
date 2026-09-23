# Custom Keyboard / IME Input Interception

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `custom_keyboard_input_interception` |
| Category | `system_provider` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-PRIVACY-1 |
| MASWE | MASWE-0040 |
| MASTG (v2 tests) | MASTG-TEST-0390 |
| CWE | CWE-200, CWE-359, CWE-522 |
| Suggested tools | adb, frida, mitmproxy, jadx |

## Description

A custom keyboard / InputMethodService (or iOS keyboard extension) captures sensitive input typed in OTHER apps - passwords, OTPs, financial data, passkey/AI prompts - and exfiltrates it or logs it because the extension has network access / lacks isolation, so the IME provider surface becomes a system-wide keylogger (Apple keyboard-extension / Android IME provider-privilege class).

## Reproduce in the app

DVMA is the harness: open **Custom Keyboard / IME Input Interception** (`custom_keyboard_input_interception`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- frida
- mitmproxy
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-PRIVACY-1
- OWASP MASWE: MASWE-0040
- OWASP MASTG (v2 tests): MASTG-TEST-0390
- CWE: CWE-200, CWE-359, CWE-522
