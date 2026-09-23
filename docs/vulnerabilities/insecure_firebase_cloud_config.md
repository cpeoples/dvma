# Insecure Firebase / Cloud Backend Config

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `insecure_firebase_cloud_config` |
| Category | `supply_chain` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M8 |
| MASVS | MASVS-STORAGE-2, MASVS-NETWORK-1, MASVS-CODE-2 |
| MASWE | MASWE-0002 |
| MASTG (v2 tests) | MASTG-TEST-0212, MASTG-TEST-0214 |
| CWE | CWE-1188, CWE-668, CWE-798 |
| Suggested tools | mitmproxy, strings, MobSF |

## Description

A world-readable Firebase/cloud backend URL plus hardcoded cloud credentials expose backend data.

## Reproduce in the app

DVMA is the harness: open **Insecure Firebase / Cloud Backend Config** (`insecure_firebase_cloud_config`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- strings
- MobSF

## Standards mapping

- OWASP Mobile Top 10 (2024): M8
- OWASP MASVS: MASVS-STORAGE-2, MASVS-NETWORK-1, MASVS-CODE-2
- OWASP MASWE: MASWE-0002
- OWASP MASTG (v2 tests): MASTG-TEST-0212, MASTG-TEST-0214
- CWE: CWE-1188, CWE-668, CWE-798
