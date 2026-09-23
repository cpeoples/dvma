# Insecure Local Storage (Plaintext SharedPreferences/UserDefaults)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `insecure_local_storage` |
| Category | `storage` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M9 |
| MASVS | MASVS-STORAGE-1 |
| MASWE | MASWE-0001 |
| MASTG (v2 tests) | MASTG-TEST-0287, MASTG-TEST-0300, MASTG-TEST-0301, MASTG-TEST-0302 |
| MASTG demos | MASTG-DEMO-0059 |
| CWE | CWE-312, CWE-922 |
| Suggested tools | objection |

## Description

Auth token and PII written to SharedPreferences/UserDefaults in cleartext.

## Reproduce in the app

DVMA is the harness: open **Insecure Local Storage (Plaintext SharedPreferences/UserDefaults)** (`insecure_local_storage`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- objection

## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP MASVS: MASVS-STORAGE-1
- OWASP MASWE: MASWE-0001
- OWASP MASTG (v2 tests): MASTG-TEST-0287, MASTG-TEST-0300, MASTG-TEST-0301, MASTG-TEST-0302
- OWASP MASTG demos: MASTG-DEMO-0059
- CWE: CWE-312, CWE-922
