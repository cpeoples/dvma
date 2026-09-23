# AI Output Rendered in WebView (XSS / local-file read)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `ai_output_to_webview_xss` |
| Category | `ai_mobile` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| OWASP LLM/GenAI Top 10 (2025) | LLM05 |
| MASVS | MASVS-PLATFORM-2, MASVS-CODE-4 |
| MASWE | MASWE-0034 |
| MASTG (v2 tests) | MASTG-TEST-0031, MASTG-TEST-0033 |
| MASTG demos | MASTG-DEMO-0096, MASTG-DEMO-0097 |
| CWE | CWE-79, CWE-73 |
| Suggested tools | garak, promptfoo, frida, objection |

## Description

LLM output is injected into a WebView via loadHtmlString/evaluateJavascript with no encoding, so model-produced (attacker-influenced) HTML/JS executes in the app origin (AI-output->XSS class; FAQ-Bot CVE-2025-63639 / ZOLL ePCR CVE-2025-12699).

## Reproduce in the app

DVMA is the harness: open **AI Output Rendered in WebView (XSS / local-file read)** (`ai_output_to_webview_xss`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- garak
- promptfoo
- frida
- objection

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP Top 10 for LLM/GenAI Applications (2025): LLM05
- OWASP MASVS: MASVS-PLATFORM-2, MASVS-CODE-4
- OWASP MASWE: MASWE-0034
- OWASP MASTG (v2 tests): MASTG-TEST-0031, MASTG-TEST-0033
- OWASP MASTG demos: MASTG-DEMO-0096, MASTG-DEMO-0097
- CWE: CWE-79, CWE-73
