# iOS Capability-Composition Chain

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `ios_capability_composition_chain` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-3, MASVS-AUTH-1 |
| MASWE | MASWE-0029, MASWE-0018 |
| CWE | CWE-441, CWE-862, CWE-668 |
| Suggested tools | ipsw, Hopper, frida |

## Description

The vulnerability is the CHAIN, not any one API. A Universal Link resolves to an App Intent -> `perform()` reads its parameter as a security-scoped file reference -> resolves a persisted bookmark -> reads Contacts and exports them, with each hop inheriting trust from the last rather than re-authorizing the untrusted link. A crafted link therefore drives a full contacts export with no user authorization, even though matching a link, running an App Intent, resolving a bookmark, and reading Contacts are each individually legitimate. The secure path treats the link as untrusted, requires fresh user authorization at the App Intent for destructive/protected-data actions, and re-validates the bookmark scope before the sink (capability-composition / confused-deputy chain).

## Reproduce in the app

DVMA is the harness: open **iOS Capability-Composition Chain** (`ios_capability_composition_chain`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- ipsw
- Hopper
- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-3, MASVS-AUTH-1
- OWASP MASWE: MASWE-0029, MASWE-0018
- CWE: CWE-441, CWE-862, CWE-668
