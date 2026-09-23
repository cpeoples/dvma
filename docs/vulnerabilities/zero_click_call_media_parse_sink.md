# Zero-Click Media Parse Before User Accept (VoIP-ring class)

> **Training only.** This is an intentional vulnerability. See the root README disclaimer.

| Field | Value |
|-------|-------|
| ID | `zero_click_call_media_parse_sink` |
| Category | `platform` |
| Difficulty | hard |
| OWASP Mobile Top 10 (2024) | M7 |
| MASVS | MASVS-CODE-4, MASVS-PLATFORM-3 |
| MASWE | MASWE-0050 |
| CWE | CWE-20, CWE-125 |
| Suggested tools | frida, radamsa |

## Description

Attacker-controlled call-setup media is parsed while the call is still ringing, before the user accepts, so a malformed payload reaches a fragile parsing sink with no user interaction (WeWorm zero-click WeChat VoIP RCE class; reproduced app-layer as an unbounded-length parse over an offline buffer).

## Exploit steps

1. Open the module and press **Deliver malicious ring frame**. The frame declares the full reassembly-buffer length but ships only a few payload bytes; the ring-time parser trusts the declared length and reads past the payload into adjacent reassembly memory, all before any user accept. The over-read region is written to a real, pullable artifact and its path is shown in the evidence panel.
2. Pull the leaked artifact off the device to confirm it is real data, not a boolean:

   ```
   adb shell run-as com.dvma cat files/dvma-artifacts/zero_click_overread.bin
   # or, from the external files dir the harness pulls:
   adb pull /sdcard/Android/data/com.dvma/files/dvma-artifacts/zero_click_call_media_parse_sink.txt
   ```
3. Note that the parse happens while the call is *ringing*: declining defeats a single attempt, but the frame can simply be re-delivered, the zero-click surface the class abuses.
4. Compare against the hardened parser, which defers all media parsing until the user accepts and bounds every read by the bytes actually present. To fuzz the class, mutate the 4-byte big-endian length header and payload (e.g. with `radamsa`).

This reproduces the WeWorm zero-click WeChat VoIP surface (Aug 2026) at the app layer: the real bug was memory corruption in a native VoIP stack, but the weakness class, parsing attacker-controlled call-setup media before user interaction and trusting a declared length over the actual bytes, is exercised here over a real arena, producing a genuine on-disk leak artifact.

## Expected tooling

- frida
- radamsa

## Standards mapping

- OWASP Mobile Top 10 (2024): M7
- OWASP MASVS: MASVS-CODE-4, MASVS-PLATFORM-3
- OWASP MASWE: MASWE-0050
- CWE: CWE-20, CWE-125
