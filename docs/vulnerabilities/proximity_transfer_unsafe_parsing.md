# Proximity Transfer Unsafe Parsing (AirDrop / Quick Share)

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `proximity_transfer_unsafe_parsing` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-2, MASVS-CODE-4 |
| MASWE | MASWE-0050 |
| CWE | CWE-776, CWE-674, CWE-20 |
| Suggested tools | radamsa |

## Description

The app parses an untrusted, pre-authentication proximity-transfer payload (AirDrop / Quick Share plist / XML / archive) with a naive, unbounded parser, so a malformed plist, a deeply-nested XML recursion bomb, or a decompression bomb causes resource exhaustion / state-machine confusion with no prior pairing (AirDrop & Quick Share proximity-protocol research class).

## Reproduce in the app

DVMA is the harness: open **Proximity Transfer Unsafe Parsing (AirDrop / Quick Share)** (`proximity_transfer_unsafe_parsing`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- radamsa

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-2, MASVS-CODE-4
- OWASP MASWE: MASWE-0050
- CWE: CWE-776, CWE-674, CWE-20
