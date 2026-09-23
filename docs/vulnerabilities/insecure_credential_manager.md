# Insecure Credential Manager / Autofill Integration

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `insecure_credential_manager` |
| Category | `auth` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-2, MASVS-STORAGE-2, MASVS-PLATFORM-3 |
| MASWE | MASWE-0019 |
| MASTG (v2 tests) | MASTG-TEST-0393, MASTG-TEST-0313, MASTG-TEST-0316 |
| MASTG demos | MASTG-DEMO-0151 |
| CWE | CWE-522, CWE-524 |
| Suggested tools | objection, frida, r2frida |

## Description

Misuses the Android Credential Manager / iOS AutoFill: associates credentials with an unverified domain and lets autofill cache secrets into insecure fields.

## Reproduce in the app

DVMA is the harness: open **Insecure Credential Manager / Autofill Integration** (`insecure_credential_manager`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- objection
- frida
- r2frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-2, MASVS-STORAGE-2, MASVS-PLATFORM-3
- OWASP MASWE: MASWE-0019
- OWASP MASTG (v2 tests): MASTG-TEST-0393, MASTG-TEST-0313, MASTG-TEST-0316
- OWASP MASTG demos: MASTG-DEMO-0151
- CWE: CWE-522, CWE-524
