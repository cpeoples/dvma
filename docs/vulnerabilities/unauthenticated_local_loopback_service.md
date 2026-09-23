# Unauthenticated Local / Loopback Service

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `unauthenticated_local_loopback_service` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-NETWORK-1, MASVS-PLATFORM-1 |
| MASWE | MASWE-0018 |
| CWE | CWE-306, CWE-668, CWE-350 |
| Suggested tools | mitmproxy, Burp Suite, adb, nc, tcpdump |

## Description

The app opens a local HTTP/TCP or unix-domain socket (for IPC, a debug bridge, a companion SDK, or a WebView bridge) with no authentication, so any co-resident app - or remote web content via DNS rebinding against 127.0.0.1 - reaches privileged functionality or reads data on that port. The loopback service is treated as trusted merely because it is local. The secure path binds an unpredictable per-session token / origin check to every local request.

## Reproduce in the app

DVMA is the harness: open **Unauthenticated Local / Loopback Service** (`unauthenticated_local_loopback_service`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- Burp Suite
- adb
- nc
- tcpdump

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-NETWORK-1, MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0018
- CWE: CWE-306, CWE-668, CWE-350
