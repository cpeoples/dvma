Most storage/privacy modules persist a **real on-device artifact** (a
`UserDefaults` plist, a SQLite DB, a temp file) and describe it as *recoverable
from an unencrypted backup or a jailbroken device*. On Android you'd just
`adb pull`; iOS has **no single "pull" verb**, so the honest recovery paths are:

- **Unencrypted device backup (no jailbreak).** Take a local backup and extract
  the app container:

  ```bash
  # Finder/iTunes: back up the device with "Encrypt local backup" OFF, or:
  idevicebackup2 backup --full ./dvma-backup          # libimobiledevice
  # Browse/extract the backup with a GUI tool (e.g. iMazing) to read the
  # app's Documents/Library (UserDefaults plist, SQLite DBs, temp files).
  ```

  This reaches app-sandbox files copied into the backup. It does **not** dump
  the Keychain (backups store Keychain items re-encrypted/keybag-wrapped).

- **Jailbroken device (full sandbox + Keychain).** A jailbreak gives you a root
  shell and broad filesystem read access, so you reach the live sandbox and can
  dump Keychain items. Set it up with **[Dopamine](/device-access/ios/run/)**
  (A12+, iOS ≤ 17.3.1) or **[palera1n](/device-access/ios/palera1n/)** (A8-A11, any
  iOS incl. 17/18); both end at the same SSH/SCP/Filza pull commands below. On a
  **rootless** jailbreak (both tools' default) apps run as **`mobile`**, so log in
  as `mobile` - see below.

### Find the device's IP address (for SSH/SCP)

`ssh root@<device-ip>` needs the phone's IP. Three ways, easiest first:

1. **On the phone (simplest):** **Settings → Wi-Fi → tap the ⓘ** next to your
   network → read **IP Address** (e.g. `192.168.0.117`). The Mac and phone must be
   on the **same network/subnet**.

2. **Find it from the Mac by MAC address (headless, recommended).** Read the
   device's Wi-Fi MAC over USB and match it in the Mac's ARP table:

   ```bash
   arp -a | awk -F'[()]' -v mac="$(ideviceinfo -k WiFiAddress)" '$0 ~ mac {print $2}'
   # -> 192.168.0.76
   ```

   > **Turn OFF Private Wi-Fi Address on the device** (Settings → Wi-Fi → ⓘ →
   > *Private Wi-Fi Address*). With it on, iOS presents a rotating random MAC
   > that won't match `ideviceinfo`'s hardware `WiFiAddress`, so the lookup fails.

   If the ARP cache is cold, prime it first with a quick subnet ping, then re-run
   the one-liner (macOS `arp` also strips leading zeros, so match loosely):

   ```bash
   SUBNET=$(ipconfig getifaddr en0 | sed 's/\.[0-9]*$/./')   # e.g. 192.168.0.
   for i in $(seq 1 254); do ping -c1 -W1 "$SUBNET$i" >/dev/null 2>&1 & done; wait
   ```

3. **Scan the subnet for the open SSH port (fallback over Wi-Fi).** A host with
   `sshd` up always answers on port 22 with a banner. Sweep the subnet and print
   whoever speaks SSH:

   ```bash
   SUBNET=$(ipconfig getifaddr en0 | sed 's/\.[0-9]*$/./')   # e.g. 192.168.0.
   for i in $(seq 1 254); do
     (nc -G1 -w1 "$SUBNET$i" 22 2>/dev/null | grep -q '^SSH-' \
        && echo "SSH up at $SUBNET$i") &
   done; wait
   ```

   The printed `SSH up at 192.168.x.y` is your device (assuming it's the only
   jailbroken phone running OpenSSH on the subnet). Confirm with
   `nc -w4 <ip> 22` → `SSH-2.0-OpenSSH…`.

### Logging in over SSH

```bash
# Force password auth so ssh doesn't exhaust key attempts ("Too many
# authentication failures") before it ever offers the password:
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no root@<device-ip>
```

- **Password** = whatever you set in Dopamine (Step 3); the classic default is
  **`alpine`**.
- **`UNIX authentication refused` / `Permission denied`** = wrong password, or
  root login is disabled. On **rootless** jailbreaks try the **`mobile`** user
  instead (`ssh mobile@<device-ip>`, then `sudo su`).
- Confirm the server is even up first (no password needed):
  `nc -w4 <device-ip> 22` should print an `SSH-2.0-OpenSSH…` banner. No banner ⇒
  OpenSSH isn't installed/running - install it via Sileo (see
  [Run the jailbreak](/device-access/ios/run/) Step 4).

### Pull the DVMA artifacts (the actual proof step)

DVMA's evidence sink writes each exercised module's real artifact to
**`Documents/dvma-artifacts/<vulnId>.txt`** inside the app's data container (and
mirrors every record to `os_log` under `DVMA-EVIDENCE`). The container lives
under a random UUID, so first locate it by its bundle id, then read/copy the
files. On a **rootless** jailbreak the container is owned by `mobile`, so the
`mobile` user can read it directly:

```bash
# 1) Find DVMA's data container by matching the bundle id in its metadata plist:
ssh mobile@<device-ip> '
  for d in /var/mobile/Containers/Data/Application/*/; do
    grep -ql com.dvma "$d/.com.apple.mobile_container_manager.metadata.plist" 2>/dev/null \
      && echo "$d";
  done'
# -> /var/mobile/Containers/Data/Application/<UUID>/

# 2) List what modules have written (empty until you EXERCISE modules in the app):
C="/var/mobile/Containers/Data/Application/<UUID>"
ssh mobile@<device-ip> "ls -la '$C/Documents/dvma-artifacts/' 2>/dev/null"

# 3) Copy every artifact off the device for review:
scp -r mobile@<device-ip>:"'$C/Documents/dvma-artifacts'" ./ios-artifacts
```

> **The artifacts only appear after a module runs.** A freshly-installed/launched
> DVMA has an empty `Documents/` (just framework caches). Open the app and
> exercise a few modules first (tap their action buttons), *then* pull - you'll
> see `<vulnId>.txt` files whose contents are the real ciphertext / plist / DB /
> file-path evidence. Cross-check with the os_log stream:
> `ssh mobile@<device-ip> 'log show --last 15m --predicate "eventMessage CONTAINS \"DVMA-EVIDENCE\"" --style compact'`.

> **Root vs. mobile.** On rootless Dopamine, apps run as `mobile` and their
> containers are `mobile`-owned, so `mobile@…` can read them (no root needed). If
> a path is root-only, escalate on-device with `sudo su` (uses the same password).


> Where a module's evidence panel says *"readable from an unencrypted backup or
> over SSH/SCP / Filza on a jailbroken device"*, those commands are exactly how
> you confirm the artifact really landed on disk.

<br/>

> **Simulator shortcut (no jailbreak).** Most modules' real I/O is pure-Dart and
> identical to Android, and the evidence sink writes to the app's Documents dir +
> os_log. On the **Simulator** that container is a plain folder on your Mac, so
> [`automation/scripts/capture_run_ios.sh`](https://github.com/cpeoples/dvma/blob/main/automation/scripts/capture_run_ios.sh)
> runs the XCUITest walk and pulls every real artifact into `report-ios.md` with
> just `simctl`, no device, backup, or jailbreak. See the
> [Automation](/getting-started/automation/) guide for the real-vs-simulated
> tiers.
