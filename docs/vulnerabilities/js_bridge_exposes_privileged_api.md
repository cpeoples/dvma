# JS Bridge Exposes a Privileged Native API

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `js_bridge_exposes_privileged_api` |
| Category | `native_bridge` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-2, MASVS-AUTH-1 |
| MASWE | MASWE-0033 |
| MASTG (v2 tests) | MASTG-TEST-0334 |
| MASTG demos | MASTG-DEMO-0097 |
| CWE | CWE-749, CWE-862, CWE-926 |
| Suggested tools | r2frida, frida, objection, mitmproxy |

## Description

A bridge method exposes a privileged native capability (auth-token read, Keychain/Keystore, filesystem, camera/location) to any web content with no origin allowlist or permission gate, so a loaded page calls it directly.

## Reproduce in the app

DVMA is the harness: open **JS Bridge Exposes a Privileged Native API** (`js_bridge_exposes_privileged_api`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- r2frida
- frida
- objection
- mitmproxy

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-2, MASVS-AUTH-1
- OWASP MASWE: MASWE-0033
- OWASP MASTG (v2 tests): MASTG-TEST-0334
- OWASP MASTG demos: MASTG-DEMO-0097
- CWE: CWE-749, CWE-862, CWE-926
