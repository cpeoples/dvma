# App Attestation Not Implemented (server never verifies client)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `app_attestation_absent` |
| Category | `resilience` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M7 |
| MASVS | MASVS-RESILIENCE-2 |
| MASWE | MASWE-0056 |
| CWE | CWE-693, CWE-345 |
| Suggested tools | frida, mitmproxy |

## Description

The backend accepts requests without an app-attestation token proving they come from a genuine, unmodified build, so a repackaged or scripted client is indistinguishable from the real app (MASWE-0056).

## Reproduce in the app

DVMA is the harness: open **App Attestation Not Implemented (server never verifies client)** (`app_attestation_absent`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- mitmproxy

## Standards mapping

- OWASP Mobile Top 10 (2024): M7
- OWASP MASVS: MASVS-RESILIENCE-2
- OWASP MASWE: MASWE-0056
- CWE: CWE-693, CWE-345
