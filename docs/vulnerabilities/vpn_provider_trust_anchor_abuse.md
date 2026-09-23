# VPN Provider Trust-Anchor / Tunnel MITM

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `vpn_provider_trust_anchor_abuse` |
| Category | `system_provider` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M5 |
| MASVS | MASVS-NETWORK-1, MASVS-NETWORK-2 |
| MASWE | MASWE-0027 |
| MASTG (v2 tests) | MASTG-TEST-0282 |
| MASTG demos | MASTG-DEMO-0154 |
| CWE | CWE-295, CWE-297, CWE-940 |
| Suggested tools | mitmproxy, Burp Suite, testssl.sh, Wireshark |

## Description

An app that provides a VPN tunnel authenticates the tunnel endpoint weakly - disabled/loose certificate validation, a custom trust manager, user-controllable CA trust, hostname-validation bypass, or an insecure fallback transport - so an adjacent attacker MITMs all traffic the tunnel is supposed to protect. Distinct from app-level pinning: the whole-device VPN provider is the trust anchor (Prisma Access VPN-agent improper-cert-validation CVE-2026-0248 class).

## Reproduce in the app

DVMA is the harness: open **VPN Provider Trust-Anchor / Tunnel MITM** (`vpn_provider_trust_anchor_abuse`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- Burp Suite
- testssl.sh
- Wireshark

## Standards mapping

- OWASP Mobile Top 10 (2024): M5
- OWASP MASVS: MASVS-NETWORK-1, MASVS-NETWORK-2
- OWASP MASWE: MASWE-0027
- OWASP MASTG (v2 tests): MASTG-TEST-0282
- OWASP MASTG demos: MASTG-DEMO-0154
- CWE: CWE-295, CWE-297, CWE-940
