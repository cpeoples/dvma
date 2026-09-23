# Unsafe Media / Image Decoding

<!-- dvma:generated-stub -->
> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `unsafe_media_decoding` |
| Category | `input_validation` |
| Difficulty | medium |
| OWASP Mobile Top 10 (2024) | M4 |
| MASVS | MASVS-CODE-4, MASVS-PLATFORM-2 |
| MASWE | MASWE-0050 |
| CWE | CWE-20, CWE-1284, CWE-409 |
| Suggested tools | ImageMagick, radamsa, frida |

## Description

Untrusted image/media bytes are passed straight to a decoder with no type/size/dimension checks, enabling decompression bombs and codec exploitation (Samsung CVE-2025-21043 class).

## Reproduce in the app

DVMA is the harness: open **Unsafe Media / Image Decoding** (`unsafe_media_decoding`) from the home index, tap the demo action, and read the on-screen evidence panel, which prints the concrete proof (leaked value, accepted replay, executed payload, or unauthorized result). Where a module provides a secure/hardened action, run it too and confirm the same attack is rejected. The published docs site renders a full step-by-step playbook for this module from the registry, including the optional on-device tooling path below.

## Expected tooling

- ImageMagick
- radamsa
- frida

## Standards mapping

- OWASP Mobile Top 10 (2024): M4
- OWASP MASVS: MASVS-CODE-4, MASVS-PLATFORM-2
- OWASP MASWE: MASWE-0050
- CWE: CWE-20, CWE-1284, CWE-409
