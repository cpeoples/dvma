# Cross-App OTP / Credential Leak

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `cross_app_otp_credential_leak` |
| Category | `auth` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-PLATFORM-1, MASVS-AUTH-2, MASVS-STORAGE-2 |
| MASWE | MASWE-0018 |
| MASTG (v2 tests) | MASTG-TEST-0366, MASTG-TEST-0364, MASTG-TEST-0374 |
| MASTG demos | MASTG-DEMO-0130, MASTG-DEMO-0128, MASTG-DEMO-0138 |
| CWE | CWE-926, CWE-200, CWE-927 |
| Suggested tools |  |

## Description

A co-resident malicious app can read OTP codes / auth deep links from this app via an unprotected exported component, broadcast, or shared clipboard (Authenticator CVE-2026-26123 class).

## Reproduce in the app

DVMA is the harness: open **Cross-App OTP / Credential Leak** (`cross_app_otp_credential_leak`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-AUTH-2, MASVS-STORAGE-2
- OWASP MASWE: MASWE-0018
- OWASP MASTG (v2 tests): MASTG-TEST-0366, MASTG-TEST-0364, MASTG-TEST-0374
- OWASP MASTG demos: MASTG-DEMO-0130, MASTG-DEMO-0128, MASTG-DEMO-0138
- CWE: CWE-926, CWE-200, CWE-927
