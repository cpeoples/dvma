Dopamine is now on the phone (from [Install Dopamine](/device-access/ios/install/)). This page
turns it on and installs OpenSSH so you can pull files off the device.

## Step 3 - Run the jailbreak

1. **Trust the developer profile** - *this depends on how you installed Dopamine*:

   | If you installed with… | Trust step |
   | --- | --- |
   | **Sideloadly / AltStore / SideStore / CLI (free Apple Account)** | **Settings → General → VPN & Device Management →** tap your developer app **→ Trust** |
   | **CLI with a paid dev / enterprise cert** | Already trusted - **skip** |
   | **TrollStore** | Already trusted (permanent signing) - **skip** |

2. **Open Dopamine → choose your package manager → set a password → Jailbreak.**
   Walk the app's screens in this order:
   1. On the main screen, tap the **Settings/gear** (or the package-manager prompt)
      and under **Package Managers** enable **Sileo** (the recommended default - the
      modern, best-maintained manager; *Zebra* is an optional alternative, you don't
      need both).
   2. **Set the root/mobile password *before* jailbreaking.** In Dopamine's settings,
      open **"Change root password"** (a.k.a. the *terminal password*) and change it
      from the default **`alpine`** to something you'll remember - this is the same
      password you'll use for **SSH (`ssh root@…`)** and **`sudo`/su** on-device.
      Do this now: after the jailbreak resprings you'd otherwise be SSHing in with the
      well-known default.
   3. Tap **Jailbreak**. Dopamine installs the bootstrap + your chosen package
      manager, then **resprings (reboots SpringBoard)**. When it comes back, Sileo is
      on your Home screen.

   > If you skipped the password step above, you can still change it afterward from a
   > terminal (Sileo → install **NewTerm**, then run `passwd`) or over SSH once OpenSSH
   > is installed (Step 4) - but change it off `alpine` before leaving the device on a
   > network.

3. **After every full reboot**, re-open **Dopamine** and tap **Jailbreak** again
   (that's what *semi-untethered* means). Your package manager and password persist;
   only the jailbreak state needs re-enabling.

> **Re-signing vs. re-jailbreaking (don't confuse them):** tapping **Jailbreak**
> after a reboot is free and instant. *Re-signing* is a separate thing that only
> matters when the **7-day** install expires - and how you renew depends on your
> installer: **Sideloadly/CLI** = re-run the install; **AltStore** = auto-refreshes
> while AltServer is on the same Wi-Fi; **SideStore** = renews on-device;
> **TrollStore** = never expires.

## Step 4 - Install OpenSSH (to pull files off the device)

Sileo is the App-Store-like package manager Dopamine just installed. Install
**OpenSSH** from it so you can log in from your Mac:

1. **Open Sileo** (on the Home screen after the jailbreak respring).
2. Tap the **Search** tab (bottom bar) and type **`ssh`**.
3. In results, tap the **openssh** package from the **Procursus Team** repo (the
   default repo Dopamine adds - you don't need to add any source).
4. Tap **Install** (top-right). Sileo drops it into a queue - tap **Queue** (bottom
   bar), then **Confirm** to run the install.
5. When it finishes, tap **Done**. If Sileo asks to **respring/restart**, allow it -
   the SSH daemon (`sshd`) starts on boot afterward.
6. *(Optional, handy)* also search-install **Filza File Manager** (browse files on
   the device itself) and **NewTerm** (an on-device terminal, e.g. to run `passwd`).

> **Don't see OpenSSH / empty results?** Pull-to-refresh the **Sources** tab so
> Sileo updates its package lists, then search **`ssh`** again. The Procursus repo
> ships with Dopamine, so you normally don't add a source; only add one manually if
> OpenSSH is genuinely missing.

**Find the device's IP** (needed for `ssh root@<device-ip>`): on the phone,
**Settings → Wi-Fi → (i) next to your network → IP Address**. The Mac and iPhone
must be on the **same network**.

Then pull artifacts off-device from your Mac. Log in with the root password **you
set in Step 3** (if you skipped that, it's still the default `alpine` - change it
now with `passwd`):

```bash
ssh root@<device-ip>                            # use the password you set in Step 3
                                                # (still `alpine`? run `passwd` now)
# Rootless app containers live under /var/mobile/Containers/Data/Application/<UUID>/
scp -r root@<device-ip>:'/var/mobile/Containers/Data/Application/<UUID>/Library' ./ios-artifacts
# On-device alternative: browse the same paths in Filza.
# Dump Keychain items:
#   keychain-dumper                # classic dumper, or
#   objection -g DVMA explore      # then: ios keychain dump   (Frida-based)
```

Finding the DVMA container UUID quickly (over SSH, on the jailbroken device):

```bash
# On the device (via SSH): list app data containers and grep for the bundle id.
ls -d /var/mobile/Containers/Data/Application/*/ | while read d; do \
  grep -ql com.dvma "$d/.com.apple.mobile_container_manager.metadata.plist" 2>/dev/null && echo "$d"; done
```

Next: **[Verify iOS artifacts →](/device-access/ios/verify/)**.
