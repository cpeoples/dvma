# Embedded Mini-App Secret Exposure

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `embedded_miniapp_secret_exposure` |
| Category | `native_bridge` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M9 |
| MASVS | MASVS-STORAGE-1, MASVS-PLATFORM-2 |
| MASWE | MASWE-0001 |
| MASTG (v2 tests) | MASTG-TEST-0320 |
| CWE | CWE-312, CWE-522, CWE-294 |
| Suggested tools | r2frida, frida, objection, sqlite3 |

## Description

An embedded web-app / Mini-App persists plaintext, replayable auth tokens (and recovery secrets such as wallet mnemonics) in WebView storage reachable over the JS<->native bridge with no origin isolation, so any embedded content or co-resident inspector reads and replays them (Telegram Mini App / TENET research class).

## Reproduce in the app

DVMA is the harness: open **Embedded Mini-App Secret Exposure** (`embedded_miniapp_secret_exposure`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- r2frida
- frida
- objection
- sqlite3

## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP MASVS: MASVS-STORAGE-1, MASVS-PLATFORM-2
- OWASP MASWE: MASWE-0001
- OWASP MASTG (v2 tests): MASTG-TEST-0320
- CWE: CWE-312, CWE-522, CWE-294
