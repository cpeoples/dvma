# Authentication-State Rollback / Restore

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `auth_state_rollback_restore` |
| Category | `storage` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-1, MASVS-STORAGE-2 |
| MASWE | MASWE-0006 |
| MASTG (v2 tests) | MASTG-TEST-0338, MASTG-TEST-0387 |
| MASTG demos | MASTG-DEMO-0101, MASTG-DEMO-0150 |
| CWE | CWE-384, CWE-613, CWE-565 |
| Suggested tools | mitmproxy, sqlite3 |

## Description

The app treats a locally-persisted session/token as authoritative and never checks freshness/revocation server-side, so restoring an OLD local state (from a backup, snapshot, or copied container) revives an already-ended or revoked session and the app believes the user is still authenticated. The secure path validates the session against a server nonce / revocation list / monotonically-increasing epoch, rejecting rolled-back state.

## Reproduce in the app

DVMA is the harness: open **Authentication-State Rollback / Restore** (`auth_state_rollback_restore`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- sqlite3

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-1, MASVS-STORAGE-2
- OWASP MASWE: MASWE-0006
- OWASP MASTG (v2 tests): MASTG-TEST-0338, MASTG-TEST-0387
- OWASP MASTG demos: MASTG-DEMO-0101, MASTG-DEMO-0150
- CWE: CWE-384, CWE-613, CWE-565
