Use this page **instead of** the Dopamine pages if your device has an **A8-A11
chip** (e.g. iPhone 6s/7/8/X, iPad 5th/6th/**7th** gen). These devices are
vulnerable to **checkm8** - a bug in the read-only **bootROM** that Apple
**cannot patch in software**. That means checkm8 devices are jailbreakable on
**any iOS version they can run**, including modern **iOS 17 / 18** builds. On
those newer versions checkm8 is the reliable path for A8-A11 (Dopamine's A8-A11
coverage is limited and version-specific, and no other software jailbreak
reaches them there).

> **Verified on:** iPad 7th gen (`iPad7,11`, **A2197**, A10 Fusion) running
> **iOS 18.7.10**, jailbroken with **palera1n v3.0.0-beta.2** on an Apple Silicon
> Mac. Result: **rootless** jailbreak (`/var/jb` → Procursus), Sileo + `apt`/`dpkg`
> present, SSH as `mobile` working. Every command below was run on that device.

[**palera1n**](https://palera.in/) is the maintained checkm8 jailbreak. On A10/A11
it is **semi-tethered**: it survives *lockscreen* but **not a full reboot** - after
every power-off/reboot you re-run palera1n over USB to re-enter the jailbroken
state. For a lab/test device that's fine.

## Does my device qualify?

| Chip | Examples | checkm8 / palera1n | iOS range |
| --- | --- | --- | --- |
| **A8-A11** | iPhone 6s/SE1/7/8/X, iPad 5/6/**7**, iPad mini 4, iPad Air 2 | ✅ **Yes** (bootROM, unpatchable) | **15.0 - 18.x** (any version the device runs) |
| A12+ | iPhone XS/11/12+ and newer | ❌ No (checkm8 doesn't apply) | Use [Dopamine](/device-access/ios/) (≤ 17.3.1; A12/A13 to 18.7.1) |

Read your exact model over USB (same tooling as Step 0 of the
[overview](/device-access/ios/)):

```bash
brew install libimobiledevice        # macOS; Linux: apt install libimobiledevice6
idevice_id -l                        # 40-char UDID (device must be Trusted + unlocked)
ideviceinfo -k ProductType           # e.g. iPad7,11  -> iPad 7th gen (A10)
ideviceinfo -k ProductVersion        # e.g. 18.7.10
```

Map `ProductType` → chip at [theapplewiki.com/wiki/Models](https://theapplewiki.com/wiki/Models).
If the chip is **A8-A11**, continue. If it's **A12 or newer**, checkm8 won't work -
go back to the [Dopamine flow](/device-access/ios/).

## What you need

- The **checkm8 device** (test device only - jailbreaking weakens security).
- A **Mac** (this guide) or **Linux** box. palera1n ships a
  `palera1n-macos-universal.dmg` and Linux tarballs.
- A **good USB cable**. On **Apple Silicon Macs**, checkm8 over USB is more
  reliable through a **powered USB-A hub** than a direct USB-C port (see
  troubleshooting).
- **No throwaway Apple Account and no 7-day re-signing** - unlike Dopamine,
  palera1n doesn't sideload an app, so there's nothing to re-sign every week.

> **Turn off your device passcode first.** On A10/A11, the SEP + passcode
> interaction can break the jailbroken state. **Settings → Face/Touch ID &
> Passcode → Turn Passcode Off** *before* jailbreaking. You can re-enable it
> after, but it's simplest to leave it off on a lab device.

## Step 1 - Download palera1n

Download **only** from the official GitHub Releases:

<https://github.com/palera1n/palera1n/releases>

- Grab the latest release (**v3.0.0-beta.2** or newer).
- On macOS, download **`palera1n-macos-universal.dmg`**, open it, and drag
  **palera1n** to `/Applications` (or run the CLI binary directly).

## Step 2 - Clear Gatekeeper (unsigned app)

palera1n isn't notarized, so macOS blocks it the first time with *"palera1n can't
be opened because it is not from an identified developer."* Approve it once:

1. Click **Cancel** on the warning (do **not** move it to Trash).
2. → **System Settings → Privacy & Security**, scroll to **Security**.
3. You'll see *"palera1n was blocked from use…"* → click **Open Anyway** →
   confirm with your Mac password / Touch ID.
4. Launch palera1n again → click **Open** in the final dialog. It now runs.

Prefer the terminal? Strip the quarantine flag instead:

```bash
xattr -dr com.apple.quarantine /Applications/palera1n.app      # GUI app
# or, for the raw CLI binary you downloaded:
xattr -d com.apple.quarantine ~/Downloads/palera1n-macos-universal && \
  chmod +x ~/Downloads/palera1n-macos-universal
```

## Step 3 - Run the jailbreak (rootless)

Open the palera1n app (or run the CLI) and choose **rootless** when asked -
that's all DVMA needs, and it's the least invasive mode.

palera1n will walk you into **DFU mode** with on-screen, timed button prompts.
**Follow them exactly** - DFU timing is strict:

- **iPad 7 / devices with a Home button:** hold **Power + Home**, then on the
  countdown release **Power** but keep holding **Home** until palera1n says
  "Detected device in DFU mode."
- **Face ID devices (iPhone X):** it's a Volume Up tap → Volume Down tap → hold
  Side button → then the Side+VolDown / release sequence palera1n prints.

palera1n then runs the checkm8 exploit, boots PongoOS, applies the kernel patches,
and installs the **Loader**. When it finishes, the device boots to Springboard
with a **palera1n Loader** app on the Home screen.

> **CLI equivalent** (if you're not using the GUI): `sudo palera1n -l` selects the
> rootless jailbreak. Add `-v` / `-Vv` for verbose output when troubleshooting.

## Step 4 - Bootstrap + install Sileo, then OpenSSH

1. Open the **palera1n Loader** app → tap **Install Sileo** (or the "rootless"
   bootstrap). The device does a **userspace reboot** and comes back with **Sileo**
   on the Home screen.
2. Open **Sileo → Search `openssh`** → install **OpenSSH** (Procursus Team) →
   **Queue → Confirm**. Let it finish its userspace reboot.

## Step 5 - SSH in

On a **rootless** palera1n jailbreak, apps and their containers are owned by
**`mobile`** (uid 501), so you log in as `mobile` - not `root`:

```bash
ssh mobile@<device-ip>          # find the IP: Settings -> Wi-Fi -> tap the (i)
```

The password is whatever OpenSSH/your bootstrap set (commonly **`alpine`** until
you change it). To avoid retyping it every command, install a key once:

```bash
# from your Mac (creates a key if you don't have one), then push it to the iPad:
[ -f ~/.ssh/id_ed25519.pub ] || ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519 -q
ssh mobile@<device-ip> 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys' < ~/.ssh/id_ed25519.pub
# now key-based login works with no password prompt:
ssh mobile@<device-ip> id       # -> uid=501(mobile) ...
```

Sanity-check you're on a real rootless jailbreak:

```bash
ssh mobile@<device-ip> 'ls -ld /var/jb; command -v apt dpkg'
# /var/jb -> /private/preboot/.../procursus   (rootless marker)
# /var/jb/usr/bin/apt   /var/jb/usr/bin/dpkg
```

## Step 6 - Install DVMA and pull artifacts

Installing the app and recovering its on-device evidence is **identical** to the
Dopamine flow - the jailbreak type doesn't change how DVMA writes artifacts.
Follow **[Verify iOS artifacts](/device-access/ios/verify/)**:

- Install DVMA (`ideviceinstaller install <Runner.ipa>` or build/run from Xcode).
- Exercise a few modules in the app so they write `Documents/dvma-artifacts/`.
- Locate the container by bundle id and `scp` the artifacts off - the
  `mobile` user can read its own container directly (no root needed on rootless).

## After a reboot (semi-tethered)

Because A10/A11 is **semi-tethered**, a full power-off/reboot leaves the device in
a **non-jailbroken** (stock) boot. To get back in: plug into the Mac, launch
palera1n, and run the **rootless** jailbreak again (Step 3). Your data, Sileo, and
OpenSSH persist - you're just re-applying the boot-time patches.

## Troubleshooting

- **DFU never detected / exploit times out (Apple Silicon Mac).** checkm8 over a
  direct USB-C port on Apple Silicon is flaky. Use a **powered USB-A hub** (with a
  Lightning-to-USB-A cable) between the Mac and device, and **unplug/replug** the
  cable right after the exploit if palera1n asks. A Linux box (or Linux VM with USB
  passthrough) is the most reliable fallback.
- **Jailbroken state lost after locking/rebooting.** Expected on A10/A11 - re-run
  palera1n (Step 3). If it's lost on *lockscreen* too, make sure the **device
  passcode is OFF** (see the note above).
- **`ssh` says `Permission denied` as `root`.** Rootless has no usable `root`
  login - use **`mobile`** (Step 5). Escalate on-device with `sudo su` if a path
  is root-only.
- **`ssh` refuses before asking for a password ("Too many authentication
  failures").** Force password auth: `ssh -o PreferredAuthentications=password -o
  PubkeyAuthentication=no mobile@<device-ip>`.
- **No SSH banner at all** (`nc -w4 <ip> 22` prints nothing). OpenSSH isn't
  installed/running - redo Step 4 in Sileo.

Next: **[Verify iOS artifacts →](/device-access/ios/verify/)**
