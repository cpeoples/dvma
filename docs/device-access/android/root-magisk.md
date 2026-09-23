Two ways to patch and flash the stock boot image with Magisk. **Option A** uses
the Magisk app's GUI; **Option B** is fully terminal-only. Both end at a rooted
device. (Prefer zero-touch? The [`root_pixel.sh` script](/device-access/android/script/) automates
the middle of Option B - extract → patch → flash → pull.)

Remember the per-device partition (from the [Android overview](/device-access/android/)): **Pixel 8a
(`akita`) → `init_boot`**, **Pixel 6a (`bluejay`) → `boot`**.

<details>
<summary><b>Option A, patch with the Magisk app (GUI)</b></summary>

0. Host prereqs: Android [platform-tools](https://developer.android.com/tools/releases/platform-tools)
   (`adb`/`fastboot`) on PATH; confirm the device and note its EXACT build (it
   must match the factory image you download).

   ```bash
   adb devices                                    # confirm the device is listed
   adb shell getprop ro.build.fingerprint         # note EXACT build
   ```

1. On the phone, enable **Developer options** (tap Build number 7×), then turn on
   both **OEM unlocking** and **USB debugging**.

2. Unlock the bootloader, **this WIPES the device**, so back up first.

   ```bash
   adb reboot bootloader
   fastboot flashing unlock                       # confirm on-device with vol+power
   fastboot reboot                                # let it re-setup once
   ```

3. Download the factory image that EXACTLY matches your build from
   [Google's factory images](https://developers.google.com/android/images)
   (`akita-…` for 8a, `bluejay-…` for 6a), then unzip twice to reach the stock
   partition image.

   ```bash
   unzip akita-<build>-factory-*.zip              # Pixel 8a (use bluejay-… for 6a)
   cd akita-<build>
   unzip image-akita-<build>.zip                  # -> init_boot.img (8a) / boot.img (6a)
   ```

4. Patch it with the Magisk app: install the APK, push the image, then in the app
   tap **Install → "Select and Patch a File"** and pick that `.img`. Magisk writes
   `magisk_patched-XXXXX.img` to `Download/`; pull it back.

   ```bash
   adb install Magisk-v*.apk                      # from the Magisk releases page
   adb push init_boot.img /sdcard/Download/       # Pixel 6a: push boot.img instead
   # …patch in the Magisk app, then:
   adb pull /sdcard/Download/magisk_patched-*.img ./magisk_patched.img
   ```

5. Flash the patched image (mind the partition name per the table above).

   ```bash
   adb reboot bootloader
   fastboot flash init_boot ./magisk_patched.img  # Pixel 8a
   # fastboot flash boot   ./magisk_patched.img   # Pixel 6a
   fastboot reboot
   ```

6. Verify root.

   ```bash
   adb shell su -c id                             # expect uid=0(root)
   ```

> **May 2026 anti-rollback (Pixel).** After a first successful boot into the
> May 2026 (or newer) build, Google recommends sideloading the matching **full
> OTA** so *both* A/B slots have a bootable bootloader, otherwise a failed
> flash can brick via the older inactive slot. See the note on the
> [factory-images page](https://developers.google.com/android/images).

Kernel-level alternatives on GKI 2.0 / kernel 5.10+ devices:
**KernelSU** (<https://kernelsu.org/>) and **APatch** (<https://apatch.dev/>).

> **Version note (2026).** Android **16** (kernel 6.12) is current; **17 (API
> 37)** is next. [Magisk v31.0](https://topjohnwu.github.io/Magisk/changes.html)
> already ships Zygisk for it, so this path carries forward.

</details>

<details>
<summary><b>Option B, fully terminal-only (no Magisk GUI)</b></summary>

The GUI's *"Select and Patch a File"* step is really just Magisk's own
**`boot_patch.sh`** running on-device. You can invoke that script directly over
`adb shell` (no root needed to *patch*, only the later flash needs an unlocked
bootloader), which makes the whole flow headless/scriptable. The Magisk **APK is
also a ZIP**, so you extract the patcher binaries straight from it. Official
tool docs: <https://topjohnwu.github.io/Magisk/tools.html> ·
<https://github.com/topjohnwu/Magisk/blob/master/docs/install.md>

> **Prefer the repo helper?** [`root_pixel.sh`](/device-access/android/script/) does this extract →
> push → `boot_patch.sh` → pull for you (and can auto-fetch Magisk + the factory
> image and flash). The by-hand sequence below is what it automates.

1. Grab the Magisk APK and unzip it locally, it's a normal ZIP archive
   ([releases](https://github.com/topjohnwu/Magisk/releases)).

   ```bash
   unzip -o Magisk-v*.apk -d magisk_apk
   ```

2. Stage everything `boot_patch.sh` needs into ONE dir on the device (`arm64-v8a`
   is correct for Pixel 8a/6a; Magisk ships its binaries as `lib*.so`).

   ```bash
   adb shell mkdir -p /data/local/tmp/mroot
   adb push magisk_apk/assets/boot_patch.sh      /data/local/tmp/mroot/
   adb push magisk_apk/assets/util_functions.sh  /data/local/tmp/mroot/
   adb push magisk_apk/assets/stub.apk           /data/local/tmp/mroot/
   adb push magisk_apk/lib/arm64-v8a/libmagiskboot.so  /data/local/tmp/mroot/magiskboot
   adb push magisk_apk/lib/arm64-v8a/libmagiskinit.so  /data/local/tmp/mroot/magiskinit
   adb push magisk_apk/lib/arm64-v8a/libmagisk64.so    /data/local/tmp/mroot/magisk64
   adb push magisk_apk/lib/armeabi-v7a/libmagisk32.so  /data/local/tmp/mroot/magisk32
   adb push init_boot.img /data/local/tmp/mroot/        # Pixel 6a: push boot.img
   ```

3. Run Magisk's patcher on-device (output is `new-boot.img` in that dir), pull it
   back, and tidy up.

   ```bash
   adb shell 'cd /data/local/tmp/mroot && chmod 755 * && sh boot_patch.sh init_boot.img'
   adb pull /data/local/tmp/mroot/new-boot.img ./magisk_patched.img
   adb shell rm -rf /data/local/tmp/mroot
   ```

4. Get **temporary** root first (recommended, boots from RAM, writes nothing to
   any partition).

   ```bash
   adb reboot bootloader
   fastboot boot ./magisk_patched.img             # boots with root, unflashed
   adb wait-for-device shell su -c id             # expect uid=0(root)
   ```

5. Make it permanent by flashing the same image (mind the partition per device).

   ```bash
   adb reboot bootloader
   fastboot flash init_boot ./magisk_patched.img  # Pixel 8a
   # fastboot flash boot   ./magisk_patched.img   # Pixel 6a
   fastboot reboot
   ```

> **Why `fastboot boot` first?** It loads the patched image into memory without
> touching the partition, if it bootloops or root doesn't take, just reboot and
> you're back to stock, no recovery needed. Only `fastboot flash` (step 5) makes
> it stick. This is the official "safe memory test" Magisk recommends.

<br/>

> **Never** patch on a different device or flash someone else's patched image,
> Magisk bakes in device/AVB specifics. Always patch the image *for the device
> you're rooting*.

</details>

Once you're rooted, go to **[Verify Android artifacts](/device-access/android/verify/)**. If a flash
goes wrong, see **[Recover a bricked device](/device-access/android/recover/)**.
