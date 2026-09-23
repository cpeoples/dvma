# Sensitive Data in Crash Reports

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `sensitive_data_in_crash_reports` |
| Category | `storage` |
| Difficulty | easy |
| OWASP Mobile Top 10 (2024) | M9 |
| MASVS | MASVS-STORAGE-1, MASVS-PRIVACY-1 |
| MASWE | MASWE-0005 |
| CWE | CWE-200, CWE-532, CWE-201 |
| Suggested tools | mitmproxy |

## Description

Secrets, tokens, PII, or full request/response bodies survive into crash / diagnostic reports (Crashlytics/Sentry breadcrumbs, exception messages, attached state, native tombstones) that are written locally and shipped to a third-party crash service, exposing data the developer assumed stayed in memory. Distinct from ordinary logging: the crash pipeline captures and EXFILTRATES app state on failure. The secure path scrubs/allowlists crash payloads.

## Reproduce in the app

DVMA is the harness: open **Sensitive Data in Crash Reports** (`sensitive_data_in_crash_reports`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy

## Standards mapping

- OWASP Mobile Top 10 (2024): M9
- OWASP MASVS: MASVS-STORAGE-1, MASVS-PRIVACY-1
- OWASP MASWE: MASWE-0005
- CWE: CWE-200, CWE-532, CWE-201
