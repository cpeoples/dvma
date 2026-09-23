Jailbreak a supported iPhone/iPad so you can recover the real on-device artifacts
DVMA writes. **There are two jailbreak tools - which one you use depends on your
chip and iOS version:**

- **A8-A11 chips (iPhone 6s/7/8/X, iPad 5/6/7, …) → [palera1n](/device-access/ios/palera1n/).**
  Uses the unpatchable **checkm8** bootROM bug, so it works on **any** iOS the
  device runs - **including iOS 17 / 18** that no software jailbreak reaches.
  (Dopamine can also cover some of these on older iOS, but checkm8 is the
  cleaner, version-independent path for A8-A11.)
- **A12+ chips → Dopamine** (the four pages below): **iOS ≤ 17.3.1** on all
  supported devices, and up to **18.7.1** on A12/A13.

> **Not sure which?** Do **Step 0** first - it reads your exact chip + iOS off the
> device, then this table tells you which tool to use.

**Dopamine flow (A12+, iOS ≤ 17.3.1; A12/A13 up to 18.7.1)** - four ordered pages, top to bottom:

1. **[Download Dopamine](/device-access/ios/download/)** - where to get it, which file to grab.
2. **[Install Dopamine on the phone](/device-access/ios/install/)** - pick ONE installer (Sideloadly
   / AltStore / SideStore / TrollStore / CLI) and follow its self-contained recipe.
3. **[Run the jailbreak](/device-access/ios/run/)** - open Dopamine, pick a package manager, install
   OpenSSH.
4. **[Verify iOS artifacts](/device-access/ios/verify/)** - pull the artifact off-device (backup,
   SSH/SCP/Filza, or the Simulator - no jailbreak needed for most modules).

**checkm8 flow (A8-A11, any iOS incl. 17/18)** → **[palera1n (checkm8 devices)](/device-access/ios/palera1n/)**,
then [Verify iOS artifacts](/device-access/ios/verify/).

**Start here on this page:** confirm your device actually qualifies (Step 0). If
it doesn't, nothing below will work - and for modern iPhones you usually *can't*
downgrade into the window (see the collapsible note).

[**Dopamine**](https://ellekit.space/dopamine/) is a **rootless, semi-untethered**
jailbreak. *"Rootless"* = only part of the filesystem is writable, but the app
sandbox is readable (which is all we need to recover DVMA's artifacts).
*"Semi-untethered"* = after every full reboot you must re-open the Dopamine app
and tap **Jailbreak** again.

## What you need before starting

- A **TEST** iPhone/iPad you don't care about (jailbreaking weakens security).
- A **computer** (Mac or Windows) for the one-time install of Dopamine onto the
  phone - *unless* you use SideStore, which only needs the computer for first
  pairing. A **USB cable**.
- A **throwaway Apple Account** (make a new free one - **do not use your real
  Apple Account**). Free-account installs **expire after 7 days** and must be
  re-installed; that's fine because you only need the app long enough to
  jailbreak.
- **(Recommended) `libimobiledevice` on the computer** so you can read the
  device's exact model/iOS and, later, pull artifacts via backup. Install it in
  **Step 0** below - it's the very first thing to do.

## Step 0 - Check your device qualifies (do this first)

**Fastest path - let your computer read it (recommended).** Before touching the
phone's menus, plug it into your Mac/PC over USB and let the device tell you its
exact model + iOS version. This is also the tooling you'll reuse later for the
backup-based [artifact verification](/device-access/ios/verify/), so installing it now costs nothing.

```bash
# macOS (Homebrew). Linux: apt install libimobiledevice6 ideviceinstaller
brew install libimobiledevice ideviceinstaller

# Plug the phone in via USB, then on the phone tap "Trust This Computer"
# (enter your passcode). Now read model + iOS straight off the device:
idevice_id -l                                   # should print a 40-char UDID
ideviceinfo -k ProductType                      # e.g. iPhone14,5  (marketing name below)
ideviceinfo -k ProductVersion                   # e.g. 17.3.1  ← this is your iOS version
```

- **No UDID / "No device found"?** The phone isn't paired yet - unlock it, re-plug
  the cable, and tap **Trust This Computer** on the phone. If it still doesn't
  appear, the cable is charge-only (try another) or you haven't accepted Trust.
- **What's `ProductType`?** Apple's internal model id. Map it to a marketing name
  at [theapplewiki.com/wiki/Models](https://theapplewiki.com/wiki/Models) (e.g.
  `iPhone14,5` = iPhone 13, `iPhone15,2` = iPhone 14 Pro), then read the chip from
  the table below. `ProductVersion` is the iOS version you match against the range.

**Manual path (no computer / prefer the phone):** on the phone go to
**Settings → General → About →** read **Model/Chip** and **iOS Version**, then
match the table:

| Your chip | Jailbreak tool + iOS range |
| --- | --- |
| **A15-A17 / M2** (iPhone 13 → 15, recent iPads) | **Dopamine**, **16.5.1 - 17.3.1** |
| **A14 / M1** (iPhone 12, iPad Air 4 / Pro M1) | **Dopamine**, **16.6 - 17.3.1** |
| **A12-A13** (iPhone XS/XR, 11) | **Dopamine**, **16.6 - 18.7.1** (and 26.0 - 26.0.1) |
| **A8-A11** (iPhone 6s/7/8/X, iPad 5/6/**7**, …) | **[palera1n](/device-access/ios/palera1n/)** (checkm8) - **any iOS the device runs, incl. 17/18** |

> **The common case:** a recent iPhone (A14+) is only jailbreakable on
> **iOS ≤ 17.3.1** with Dopamine. If it's on **17.4+**, Dopamine can't jailbreak
> it and there's no checkm8 path either. See **"Can I downgrade to get into the
> window?"** below - for these chips the honest answer is *almost always no.*
>
> **A8-A11 are the exception:** checkm8 is a hardware bug, so **[palera1n](/device-access/ios/palera1n/)**
> jailbreaks them on **any** iOS version - even iOS 18 - with no signing window to
> worry about. (Verified here on an iPad 7 / A10 running iOS 18.7.10.)

<details>
<summary><strong>Can I downgrade to get into the jailbreakable window? (IPSW / signing reality)</strong></summary>

Short version: **usually no**, and specifically **no for the A14-A17 / M1-M2
iPhones this guide targets**. Downgrading iOS is gated by Apple's cryptographic
signing, not by having the firmware file:

- **You can only restore an iOS version Apple is still *signing* for your exact
  model.** "Signing" = Apple's per-device authorization checked at restore time.
  Once the window closes you can't install that version with the normal restore,
  **even if you already downloaded the IPSW.** These windows now close within
  **days** of a new release (often almost immediately) - so pre-downloading an
  IPSW does **not** preserve your ability to use it.
- **After signing stops**, the only route is `futurerestore` with **saved SHSH2
  blobs** for that version - *and* the target must be compatible with the
  **latest SEP + baseband**, *and* on **iOS 16+** with **Cryptex1**, which is
  almost always incompatible with older versions.
- **On A12 and later (all of Dopamine's A14-A17 / M1-M2 targets), downgrading
  from iOS 17 across versions is not possible** - Cryptex/nonce constraints make
  saved blobs useless. Real downgrade options survive mainly on **checkm8
  A7-A11** devices.

**So the only "downgrade" that helps a normal user is a standard restore performed
*while the target is still signed*.** If a compatible version is *currently*
signed for your model, you can move to it like this:

1. Check what's signed for your model **right now** (e.g. `ipsw.me`) - do this
   first; if nothing suitable is signed, stop, downgrading won't work.
2. Download the matching **official IPSW** for your exact model from Apple
   (e.g. via [`ipsw`](https://blacktop.github.io/ipsw/): `ipsw download ipsw
   --device iPhone... --version <signed-version>`), or Finder/iTunes.
3. Back up first (a downgrade **erases** the device). Put the device in Recovery
   (or DFU), then in **Finder/iTunes hold Option/Shift and click *Restore*** and
   pick the IPSW - or `ipsw` / `idevicerestore`. This only succeeds while Apple
   still signs it.

> **Blobs are a "save now, maybe use later" insurance** and only pay off on
> checkm8 (A7-A11) or within-patch cases - not on A12+ from iOS 17. If you want
> them anyway, save SHSH2 blobs with [`tsschecker`](https://github.com/1Conan/tsschecker)
> **while the version is signed**; restoring them later still needs SEP/baseband/
> Cryptex compatibility (usually absent on modern devices).

**Bottom line:** don't count on downgrading a modern iPhone into the jailbreak
window. Source a device **already on** a supported version instead.

</details>

Once your device qualifies, continue to the right tool for your chip:
**A8-A11 → [palera1n →](/device-access/ios/palera1n/)**, or
**A12+ on iOS ≤ 17.3.1 (A12/A13 up to 18.7.1) → [Download Dopamine →](/device-access/ios/download/)**.
