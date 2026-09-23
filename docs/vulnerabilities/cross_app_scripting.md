# Cross-App Scripting (Untrusted Intent -> Exported Activity -> WebView JS)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `cross_app_scripting` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-2, MASVS-CODE-4 |
| MASWE | MASWE-0035, MASWE-0032 |
| MASTG (v2 tests) | MASTG-TEST-0332, MASTG-TEST-0031 |
| MASTG demos | MASTG-DEMO-0095 |
| CWE | CWE-79, CWE-749, CWE-940 |
| Suggested tools | adb, drozer, jadx |

## Description

An exported activity takes an attacker-controlled Intent value and passes it to WebView loadUrl()/evaluateJavascript() without validation, giving JS execution in the trusted origin (Google's named Cross-App Scripting class; Element CVE-2024-26131/26132, FireDown CVE-2024-31974, TikTok CVE-2024-45240).

## Reproduce in the app

DVMA is the harness: open **Cross-App Scripting (Untrusted Intent -> Exported Activity -> WebView JS)** (`cross_app_scripting`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-2, MASVS-CODE-4
- OWASP MASWE: MASWE-0035, MASWE-0032
- OWASP MASTG (v2 tests): MASTG-TEST-0332, MASTG-TEST-0031
- OWASP MASTG demos: MASTG-DEMO-0095
- CWE: CWE-79, CWE-749, CWE-940
