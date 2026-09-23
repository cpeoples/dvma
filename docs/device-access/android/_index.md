Root a Pixel with **Magisk** so you can recover the real on-device artifacts DVMA
writes. Work through these pages in order:

1. **[Root with Magisk](/device-access/android/root-magisk/)** - the full manual flow (GUI *or*
   terminal-only): unlock, patch the stock boot image, flash it, verify root.
2. **[Autonomous script (`root_pixel.sh`)](/device-access/android/script/)** - the repo helper that
   auto-fetches Magisk + the matching factory image and can flash for you.
3. **[Recover a bricked device](/device-access/android/recover/)** - dm-verity/AVB notes, bootloop
   triage, and a full re-flash back to stock.
4. **[Verify Android artifacts](/device-access/android/verify/)** - pull the artifact with `adb`
   (debuggable build) or `su`/`frida` (rooted).

> **Two steps can't be scripted or downloaded for you.** Unlocking the
> bootloader (`fastboot flashing unlock`) needs a physical on-device
> confirmation and **wipes the phone**, and the boot image you patch must come
> from the factory build that **exactly matches** `ro.build.fingerprint`. So you
> always: (1) unlock by hand, (2) download the matching factory image yourself
> (or let the [script](/device-access/android/script/) fetch + verify it). The script automates
> everything *between* those - extract → patch → (optionally) flash → pull.

## The one per-device difference

**Magisk** is systemless root: patch your device's stock boot image with the
Magisk app, then flash it via fastboot. The **only per-device difference** is
which partition you patch, and that's decided by the Android version the device
**launched** with (not its model number):

- **Pixel 6 / 6 Pro / 6a** launched on Android 12 (legacy GKI) → patch **`boot`**.
- **Pixel 7, 8, 9, 10, 11 and up** launched on Android 13+ (GKI 2.0) → patch
  **`init_boot`**. (Under GKI 2.0, `boot` holds only the raw kernel; the ramdisk
  Magisk needs moved to `init_boot`.)

Everything else in the flow is identical. The [`root_pixel.sh` script](/device-access/android/script/)
**auto-detects the right partition** from the factory image, so it works across
the whole Pixel line, not just the two verified below.

Docs: <https://topjohnwu.github.io/Magisk/install.html> · Releases:
<https://github.com/topjohnwu/Magisk/releases> · Pixel factory images:
<https://developers.google.com/android/images>

| Device | Codename | SoC | Launch Android | Partition to patch/flash |
| -------- | ---------- | ----- | ---------------- | -------------------------- |
| Pixel 6 / 6 Pro / 6a | `oriole` / `raven` / `bluejay` | Tensor G1 | 12 | **`boot`** |
| Pixel 7 / 7 Pro / 7a | `panther` / `cheetah` / `lynx` | Tensor G2 | 13 | **`init_boot`** |
| Pixel 8 / 8 Pro / 8a | `shiba` / `husky` / `akita` | Tensor G3 | 14 | **`init_boot`** |
| Pixel 9 and up | (varies) | Tensor G4+ | 14/15+ | **`init_boot`** |

> **Verified on** the **Pixel 8a** (`akita`) and **Pixel 6a** (`bluejay`).
> Other Pixels follow the same launch-version rule and the script handles them
> automatically, but they haven't been hand-tested here.

Start with **[Root with Magisk →](/device-access/android/root-magisk/)**.
