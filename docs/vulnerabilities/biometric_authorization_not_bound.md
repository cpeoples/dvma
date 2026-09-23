# Biometric Result Not Bound to Operation

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `biometric_authorization_not_bound` |
| Category | `auth` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-2, MASVS-AUTH-1 |
| MASWE | MASWE-0020 |
| MASTG (v2 tests) | MASTG-TEST-0327, MASTG-TEST-0266, MASTG-TEST-0267 |
| MASTG demos | MASTG-DEMO-0090 |
| CWE | CWE-287, CWE-1021, CWE-306 |
| Suggested tools | frida, objection, r2frida, frida-trace |

## Description

The biometric prompt returns a boolean success that is NOT cryptographically bound to the specific operation being authorized (no CryptoObject / no signed server challenge), and the prompt UI can be overlaid, so a success is replayed or spoofed onto a different sensitive operation - authorization is decoupled from the biometric event (Android BiometricPrompt overlay CVE-2025-48528 class). Distinct from a trivially-bypassed prompt.

## Reproduce in the app

DVMA is the harness: open **Biometric Result Not Bound to Operation** (`biometric_authorization_not_bound`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- objection
- r2frida
- frida-trace

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-2, MASVS-AUTH-1
- OWASP MASWE: MASWE-0020
- OWASP MASTG (v2 tests): MASTG-TEST-0327, MASTG-TEST-0266, MASTG-TEST-0267
- OWASP MASTG demos: MASTG-DEMO-0090
- CWE: CWE-287, CWE-1021, CWE-306
