# Custom / Signature Permission Squatting

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `custom_signature_permission_squatting` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1 |
| MASWE | MASWE-0018, MASWE-0032 |
| CWE | CWE-732, CWE-280, CWE-284 |
| Suggested tools | adb, drozer, apktool, jadx |

## Description

An IPC component is 'protected' by a custom permission whose `protectionLevel` is `normal`/`dangerous` (not `signature`), or by a permission name a malicious app can DEFINE FIRST (install-order squatting), so the guard is trivially obtained or owned by the attacker - the interface the developer believes is protected is externally reachable. Manifest-level and deterministic. The secure path uses a `signature` protection level and verifies the caller's signing identity, not merely permission possession (Android permission-squatting class).

## Reproduce in the app

DVMA is the harness: open **Custom / Signature Permission Squatting** (`custom_signature_permission_squatting`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- adb
- drozer
- apktool
- jadx

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1
- OWASP MASWE: MASWE-0018, MASWE-0032
- CWE: CWE-732, CWE-280, CWE-284
