# SSL Pinning (Trivially Bypassable)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `ssl_pinning_bypass` |
| Category | `network` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M5 |
| MASVS | MASVS-NETWORK-2 |
| MASWE | MASWE-0028 |
| MASTG (v2 tests) | MASTG-TEST-0244, MASTG-TEST-0242 |
| CWE | CWE-295 |
| Suggested tools | frida, objection, r2frida, mitmproxy, Burp Suite |

## Description

Pinning is implemented but disabled by a client-side flag / easy hook.

## Reproduce in the app

DVMA is the harness: open **SSL Pinning (Trivially Bypassable)** (`ssl_pinning_bypass`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- objection
- r2frida
- mitmproxy
- Burp Suite

## Standards mapping

- OWASP Mobile Top 10 (2024): M5
- OWASP MASVS: MASVS-NETWORK-2
- OWASP MASWE: MASWE-0028
- OWASP MASTG (v2 tests): MASTG-TEST-0244, MASTG-TEST-0242
- CWE: CWE-295
