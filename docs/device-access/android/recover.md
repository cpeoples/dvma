If a flash goes wrong, work through this page from the top: most "it won't boot"
cases are a wrong-partition flash or a skipped reboot, not a real brick. A true
brick (no Android, no bootloader) still recovers with a full factory re-flash.

## dm-verity / AVB, do you need `--disable-verity`?

**Normally no.** Patching `init_boot`/`boot` only changes the boot ramdisk, not
the verity-protected `system`/`vendor` partitions, so Magisk handles the AVB
flags for you and you **flash only the patched boot image**, leave `vbmeta`
alone. Magisk's own docs list the `vbmeta` patch as *optional*, and it can wipe
data, so don't run it unless you actually need it. Only if a *first* boot after
flashing bootloops do you fall back to explicitly disabling verification (this
**wipes** the device):

```bash
fastboot --disable-verity --disable-verification flash vbmeta vbmeta.img
```

## If it bootloops after flashing

Almost always one of three things, in order of likelihood:

- **Flashed the wrong partition.** The patched image is `init_boot` on the
  Pixel 8a and `boot` on the 6a, flash it to *that* partition only. Flashing an
  `init_boot` image to `boot` (or both) is the #1 cause of a "Boot Failure".
- **Didn't reboot once after unlocking.** After `fastboot flashing unlock`, let
  the phone boot to Android once before flashing the patched image.
- **Recover without wiping:** the other A/B slot is still stock, so switch to it
  and boot, then re-patch cleanly.

  ```bash
  fastboot --set-active=other && fastboot reboot   # boot the stock slot
  # or re-flash the STOCK boot/init_boot.img you kept from the factory zip:
  fastboot flash init_boot init_boot.img           # Pixel 8a (boot for 6a)
  ```

> Keep the **stock** `init_boot.img`/`boot.img` from the factory zip, it's your
> one-command way back. Never restore `vbmeta` to stock on a patched device.

## Recovering a bricked device (full factory re-flash)

If the quick fixes above don't help - or the device won't boot Android at all -
restore it completely to stock by flashing the **full factory image**. As long
as you can still reach **fastboot** (`fastboot devices` lists it), the device is
recoverable. Two equivalent routes:

### Route 1 - `flash-all` (terminal)

Every Google factory zip ships a `flash-all.sh` (`flash-all.bat` on Windows)
that flashes **every** partition back to stock. This is the surest full-reset.

```bash
# 1) Download the factory image that matches your device from
#    https://developers.google.com/android/images  (akita = 8a, bluejay = 6a),
#    then unzip it.
unzip akita-<build>-factory-*.zip
cd akita-<build>

# 2) Boot into the bootloader and run flash-all (this ERASES the device).
adb reboot bootloader            # or hold Power+Vol-Down
./flash-all.sh                   # flash-all.bat on Windows
```

> `flash-all` **wipes user data** and rewrites bootloader, radio, and both A/B
> slots - so it also clears a bad inactive slot. If you edited `flash-all` to
> keep data with `-w` removed on a previously bricked device, don't: on a brick,
> take the clean wipe.

**Scripted:** [`root_pixel.sh --recover`](/device-access/android/script/) does the whole route for
you - it re-downloads the correct factory zip (via Google's Flash Tool API),
**verifies its SHA-256 prefix**, unzips it, and runs `flash-all` (typed confirmation unless `--yes`):

```bash
automation/scripts/root_pixel.sh --recover            # auto-detect build, confirm, flash-all
automation/scripts/root_pixel.sh --recover=<build-id> # pin an exact build
automation/scripts/root_pixel.sh --recover --yes      # unattended
```

### Route 2 - Android Flash Tool (GUI fallback)

If you don't have platform-tools set up, or `flash-all` errors out, use Google's
official **web** flasher - it drives fastboot from Chrome/Edge and needs no local
install:

<https://flash.android.com/>

1. Unlock the bootloader if it isn't already (**Settings → Developer options →
   OEM unlocking**, then the tool walks you through `flashing unlock`).
2. Connect the device in **fastboot/bootloader** mode over USB.
3. Pick your device's current build, keep **"Wipe device"** checked for a brick,
   and let it flash. It handles both A/B slots and the bootloader.

> **Still nothing?** If the device won't even enter fastboot, use **EDL/`fastbootd`
> recovery** per the device's community guide - but for Pixels, a fastboot-level
> `flash-all` recovers essentially every soft-brick.

Once you're back to stock, re-root from **[Root with Magisk](/device-access/android/root-magisk/)**.
