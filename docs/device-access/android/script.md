[`automation/scripts/root_pixel.sh`](https://github.com/cpeoples/dvma/blob/main/automation/scripts/root_pixel.sh)
is the repo's headless rooting pipeline. It runs Magisk's **own** on-device
patcher (`assets/boot_patch.sh`, extracted from the Magisk APK) over `adb shell`

- exactly what the app's *"Install → Select and Patch a File"* button does - so
the whole flow is scriptable.

> **Prereqs:** the bootloader is **already unlocked** (a one-time, on-device,
> device-wiping step - see [Root with Magisk](/device-access/android/root-magisk/)), and `adb`,
> `fastboot`, `unzip`, `curl`, and `apksigner`/`keytool` are on PATH.

## Start here - brand-new device, just plugged in

If you literally just connected a fresh Pixel, do these **once** first (they
need physical taps and the unlock **factory-wipes** the phone - no script can do
them for you). Then the one autonomous command below does the rest.

1. **Get the repo + host tools on your computer.** Open a terminal:

   ```bash
   git clone https://github.com/cpeoples/dvma && cd dvma   # then run all commands from here
   # Install Android platform-tools (adb/fastboot) + verify tools:
   #   macOS:  brew install --cask android-platform-tools && brew install openjdk   # keytool
   #   Linux:  sudo apt-get install -y android-sdk-platform-tools android-sdk-build-tools default-jdk
   adb version && fastboot --version                       # confirm they're on PATH
   ```

2. **On the phone - enable Developer options + the two toggles.** Settings →
   About phone → tap **Build number** 7×. Then Settings → System → **Developer
   options** → turn ON **USB debugging** *and* **OEM unlocking**.

3. **Authorize this computer.** With the phone plugged in:

   ```bash
   adb devices        # unlock the phone screen and tap "Allow USB debugging"
                      #  (tick "Always allow from this computer"). It must show: <serial>  device
   ```

4. **Unlock the bootloader (this ERASES the phone - back up first).**

   ```bash
   adb reboot bootloader
   fastboot flashing unlock     # confirm ON THE PHONE with the volume/power keys
   fastboot reboot              # let it boot + finish setup once, then re-enable USB debugging
   ```

Now you're "unlocked + authorized" and the autonomous command below will run
end-to-end.

> **Which Pixel?** This is hand-verified on the **Pixel 8a** (`akita`) and
> **Pixel 6a** (`bluejay`), but the script **auto-detects the root partition
> from the factory image**, so it works across the whole line - **Pixel 6/6a
> (`boot`)** and **Pixel 7/8/9/10/11 and up (`init_boot`)**. See
> [Root with Magisk](/device-access/android/root-magisk/) for the partition rule.

## Fully autonomous (unlocked + authorized device)

Once the four steps above are done (or on any already-unlocked, already-authorized
device), **this one command** fetches everything, patches, and flashes with no
manual steps in between - just run it from the repo root:

```bash
# Auto-fetch Magisk + the exact matching factory image, patch, then flash:
automation/scripts/root_pixel.sh --fetch-magisk --fetch-image --flash --yes
```

**What happens when you run it:** it auto-selects your connected device, detects
its exact build, downloads + verifies Magisk and the matching factory image,
patches the boot image on-device, then flashes it. On some Pixels you may get
**one on-screen "confirm" during flash** - tap it.

> **You'll see `Failed to patch` a few times - that's normal, not an error.**
> Those lines come from Magisk's own `magiskboot` trying its **Samsung-only**
> kernel patches (RKP / defex / PROCA). A Pixel's Tensor kernel doesn't contain
> those patterns, so they're **skipped**. Success is confirmed by the script
> reporting `new-boot.img produced` right after - which it prints explicitly.

**The last step is Magisk's own one-time enablement, and it's GUI-gated by
design.** After the reboot the script installs the **full** Magisk app for you
(so you're *not* asked to "download full Magisk"), then guides you through
Magisk's two one-time taps. topjohnwu ships **no CLI** to pre-authorize these, so
on a **first** root they're the only interaction:

1. If Magisk shows **"Requires additional setup"**, tap **OK** - it runs its
   environment setup and reboots itself.
2. Open Magisk → **Superuser** tab → turn **ON** the switch for
   **`[SharedUID] Shell` (`com.android.shell`)**. That's what actually lets the
   ADB shell get root - until it's on, Magisk silently rejects `su` (no popup).

The script then **persists** the grant (`root_access=Apps and ADB` + an allow
policy for UID 2000) so **every later run is fully zero-touch** - root survives
reboots with no taps. Verify anytime with `adb shell su -c id` (expect
`uid=0(root)`).

> **Want it hands-free?** Add **`--auto-finalize`** and the script will *attempt*
> both taps for you via on-device UI automation (`uiautomator` + `input tap`):
>
> ```bash
> automation/scripts/root_pixel.sh --fetch-magisk --fetch-image --flash --yes --auto-finalize
> ```
>
> It locates controls **structurally** - by Magisk's own view ids
> (`com.topjohnwu.magisk:id/…`) and the non-localized package name
> `com.android.shell`, then taps the switch nearest that row - so it isn't tied to
> screen coordinates or the UI language. It's still **best-effort**: if a future
> Magisk changes those ids/layout it can't match, in which case it prints the two
> manual steps above and waits. It never writes anything extra; it only taps the
> same controls you would.

> **Nervous about the destructive step?** Drop `--flash --yes` and add
> `--boot-test` (next section) to do a no-write dry run first, or keep `--flash`
> **without** `--yes` to get a typed **FLASH** confirmation prompt before it writes.

- `--fetch-magisk` downloads the Magisk APK from the official GitHub releases and
  **verifies the signer certificate** (pinned to topjohnwu's key) before using it.
- `--fetch-image` detects the device's EXACT build, downloads the matching Google
  **factory image** (via the Flash Tool API - works for any Pixel),
  **verifies its SHA-256 prefix**, and extracts the correct
  partition (`init_boot` for 8a, `boot` for 6a).
- `--flash` is the **only** switch that writes to a partition. Without it the
  script is non-destructive (produces `./magisk_patched.img` and stops).
- `--yes` skips the typed confirmation for unattended/fleet runs.

## Safer dry run (fetch + patch, no write)

```bash
# Fetch + patch, then TEMPORARILY boot from RAM to sanity-check root (writes nothing):
automation/scripts/root_pixel.sh --fetch-magisk --fetch-image --boot-test
```

## Classic patch-only (you supply both inputs)

```bash
automation/scripts/root_pixel.sh --apk Magisk-v30.7.apk --image init_boot.img         # Pixel 8a
automation/scripts/root_pixel.sh --apk Magisk-v30.7.apk --image boot.img --boot-test  # Pixel 6a
# -> writes ./magisk_patched.img; then flash it yourself (right partition per device).
```

## Flags

| Flag | What it does |
| --- | --- |
| `--apk PATH` | Magisk `.apk` to extract the patcher from (or use `--fetch-magisk`). |
| `--fetch-magisk[=vTAG]` | Download + verify the Magisk APK from official releases (latest or a pinned tag). |
| `--sha256 HEX` | Optional expected SHA-256 of the fetched/supplied APK. |
| `--image PATH` | Stock `init_boot.img` (8a) / `boot.img` (6a) to patch (or use `--fetch-image`). |
| `--fetch-image[=BUILD]` | Auto-detect device + build, download the Google factory image (Flash Tool API) + verify its SHA-256 prefix, extract the partition. |
| `--flash` | **DESTRUCTIVE.** Flash the patched image and verify root. Typed confirm unless `--yes`. |
| `--auto-finalize` | After flashing, best-effort UI automation of Magisk's one-time enablement (confirm "additional setup", turn on the `com.android.shell` su switch), then persist. Structure-based; falls back to guided manual steps. |
| `--recover[=BUILD]` | **DESTRUCTIVE.** Re-download + verify the full factory zip and run its `flash-all` to restore stock. Typed confirm unless `--yes`. |
| `--yes` / `-y` | Skip the interactive confirmation (unattended). |
| `--serial SERIAL` | Target this exact device (`adb -s`). Required when more than one device is connected. |
| `--keep-downloads[=DIR]` | Keep + **reuse** the fetched Magisk APK and factory image (persistent cache, default `./dvma-downloads`; skips re-download when the cached image verifies). |
| `--out PATH` | Where to write the patched image (default `./magisk_patched.img`). |
| `--arch ABI` | Device ABI for the Magisk binaries (default `arm64-v8a`). |
| `--boot-test` | After patching, `fastboot boot` (temporary root, nothing written) and check root. |
| `-h` / `--help` | Show the built-in help. |

## Where do downloads go?

By default the Magisk APK and factory image live in a **temp dir that's deleted
on exit** - so a repeat run re-downloads the (multi-GB) factory image. Pass
`--keep-downloads[=DIR]` to keep them in a **persistent cache** (default
`./dvma-downloads`); on later runs the script **reuses the cached factory image
if its SHA-256 prefix still verifies** (no re-download) and **resumes** an
interrupted transfer. The patched image is written to `--out` (default
`./magisk_patched.img`). Those paths are git-ignored so you can't accidentally
commit device-specific images.

> **Tip while iterating:** run with `--keep-downloads` so you only download the
> ~3-4 GB factory image once, even across multiple attempts.

## What can't be zero-touch

Hardware/OS policy makes three steps require a physical touch (no script can do
them): the **bootloader unlock** (volume-key confirm + factory wipe), the
**first USB-debugging authorization** ("Allow?" tap), and, on some Pixels, an
**on-screen confirm** for `fastboot boot`/`flash`. So the realistic ceiling is
*one-tap enroll, then fully unattended*.

If a flash leaves the device unbootable, see **[Recover a bricked device →](/device-access/android/recover/)**.
