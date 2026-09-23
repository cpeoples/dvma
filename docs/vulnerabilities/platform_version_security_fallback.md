# Platform-Version Security Fallback

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `platform_version_security_fallback` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M8 |
| MASVS | MASVS-PLATFORM-1, MASVS-CODE-4 |
| MASWE | MASWE-0041 |
| MASTG (v2 tests) | MASTG-TEST-0245 |
| MASTG demos | MASTG-DEMO-0025 |
| CWE | CWE-636, CWE-1188, CWE-693 |
| Suggested tools | jadx |

## Description

A security decision is gated on the OS version (`if (SDK_INT >= X)` / `@available`) and silently falls back to an INSECURE path on older versions - e.g. skipping StrongBox/hardware-key backing, biometric class checks, or a network-security-config protection - so devices below the threshold run without the protection the code appears to provide. The secure path fails closed (refuses the sensitive op) when the platform can't provide the guarantee (Android/iOS version-fallback class, MASTG-TEST-0245).

## Reproduce in the app

DVMA is the harness: open **Platform-Version Security Fallback** (`platform_version_security_fallback`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M8
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-CODE-4
- OWASP MASWE: MASWE-0041
- OWASP MASTG (v2 tests): MASTG-TEST-0245
- OWASP MASTG demos: MASTG-DEMO-0025
- CWE: CWE-636, CWE-1188, CWE-693
