# Document Picker -> Trusted-File Confusion

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `document_picker_trusted_file_confusion` |
| Category | `platform` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-PLATFORM-1, MASVS-CODE-4 |
| MASWE | MASWE-0050 |
| CWE | CWE-20, CWE-829, CWE-73 |
| Suggested tools | frida, objection, r2frida, ipsw, class-dump, Hopper, r2ghidra, Ghidra |

## Description

The app assumes a file returned by the system document / file picker (or a security-scoped URL) is trustworthy simply because the OS handed it over, and feeds its path / type / contents into a sensitive sink with no re-validation, so an attacker-controlled document provider supplies a malicious path/type that the app trusts - the opposite direction to an over-broad FileProvider (Apple Document Picker / security-scoped URL trust-confusion class).

## Reproduce in the app

DVMA is the harness: open **Document Picker -> Trusted-File Confusion** (`document_picker_trusted_file_confusion`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- frida
- objection
- r2frida
- ipsw
- class-dump
- Hopper
- r2ghidra
- Ghidra

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-PLATFORM-1, MASVS-CODE-4
- OWASP MASWE: MASWE-0050
- CWE: CWE-20, CWE-829, CWE-73
