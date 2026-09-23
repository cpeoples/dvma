# Exported Component -> Arbitrary URL / Activity Launch

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `exported_component_arbitrary_url_activity` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1 |
| MASWE | MASWE-0032 |
| MASTG (v2 tests) | MASTG-TEST-0364 |
| MASTG demos | MASTG-DEMO-0128 |
| CWE | CWE-926, CWE-749, CWE-601 |
| Suggested tools | adb, drozer, jadx |

## Description

An exported component takes an attacker-supplied URL/activity target and opens it with the app's identity/privileges (ABEMA CVE-2024-28745 / Samsung Members CVE-2026-20985 & CVE-2025-21079 class).

## Reproduce in the app

DVMA is the harness: open **Exported Component -> Arbitrary URL / Activity Launch** (`exported_component_arbitrary_url_activity`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0032
- OWASP MASTG (v2 tests): MASTG-TEST-0364
- OWASP MASTG demos: MASTG-DEMO-0128
- CWE: CWE-926, CWE-749, CWE-601
