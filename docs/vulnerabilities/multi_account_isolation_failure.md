# Multi-Account Isolation Failure

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `multi_account_isolation_failure` |
| Category | `auth` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M3 |
| MASVS | MASVS-AUTH-1, MASVS-STORAGE-1 |
| MASWE | MASWE-0024 |
| CWE | CWE-459, CWE-200, CWE-613 |
| Suggested tools | mitmproxy, sqlite3, frida |

## Description

Switching accounts (or logging out and into account B) does not fully clear account A's cached credentials, tokens, keys, or on-disk/in-memory data, so account B can read or act with account A's data - and old sessions survive logout. The isolation boundary between accounts on one device fails. The secure path scopes all per-account state to the active principal and wipes/rotates it on switch and logout.

## Reproduce in the app

DVMA is the harness: open **Multi-Account Isolation Failure** (`multi_account_isolation_failure`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- mitmproxy
- sqlite3
- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M3
- OWASP MASVS: MASVS-AUTH-1, MASVS-STORAGE-1
- OWASP MASWE: MASWE-0024
- CWE: CWE-459, CWE-200, CWE-613
