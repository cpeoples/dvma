# Unsigned / Unverified Build Artifact

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `unsigned_unverified_build_artifact` |
| Category | `supply_chain` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M2 |
| MASVS | MASVS-RESILIENCE-3, MASVS-CODE-1 |
| MASWE | MASWE-0057 |
| CWE | CWE-347, CWE-494 |
| Suggested tools |  |

## Description

Update artifact fetched and applied with no signature/checksum check.

## Reproduce in the app

DVMA is the harness: open **Unsigned / Unverified Build Artifact** (`unsigned_unverified_build_artifact`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling



## Standards mapping

- OWASP Mobile Top 10 (2024): M2
- OWASP MASVS: MASVS-RESILIENCE-3, MASVS-CODE-1
- OWASP MASWE: MASWE-0057
- CWE: CWE-347, CWE-494
