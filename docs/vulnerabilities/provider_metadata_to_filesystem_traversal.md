# Provider-Controlled Metadata -> Plugin Filesystem Traversal

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `provider_metadata_to_filesystem_traversal` |
| Category | `native_bridge` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-STORAGE-2 |
| MASWE | MASWE-0032 |
| MASTG demos | MASTG-DEMO-0139 |
| CWE | CWE-22, CWE-73, CWE-20 |
| Suggested tools |  |

## Description

A framework/plugin layer (Flutter/React Native/Cordova/Capacitor) reads DISPLAY_NAME from an UNTRUSTED ContentProvider via ContentResolver.query() and uses it in filesystem path construction with no sanitization, so a malicious provider returns a `../` filename and the plugin writes/reads outside its intended cache - a plugin-boundary traversal where the dangerous code lives behind an innocent-looking app API (Flutter file_picker CVE-2026-38093 class).

## Reproduce in the app

DVMA is the harness: open **Provider-Controlled Metadata -> Plugin Filesystem Traversal** (`provider_metadata_to_filesystem_traversal`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-STORAGE-2
- OWASP MASWE: MASWE-0032
- OWASP MASTG demos: MASTG-DEMO-0139
- CWE: CWE-22, CWE-73, CWE-20
