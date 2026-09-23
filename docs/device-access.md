Most storage/privacy modules write a **real on-device artifact** (a
SharedPreferences/`UserDefaults` entry, a SQLite DB, a temp file, a Keychain
item). To confirm a finding is real you recover that artifact off-device. This
section covers getting the device access you need, per platform, plus the
`adb`/backup/Simulator recovery paths that need no root/jailbreak.

> ⚠️ **Test devices only.** Rooting/jailbreaking strips the platform security
> model (Apple's and Google's own warnings: vulnerabilities, instability, no
> future OTA updates). DVMA is intentionally insecure, keep it on **throwaway
> hardware**, never a daily driver, and never a device holding real data.

## Pick your platform

Each platform is broken into short, ordered sub-pages (open the section in the
left menu) so you only read the step you're on:

- **[Android](/device-access/android/)** - root a Pixel 8a/6a with **Magisk**:
  [Root with Magisk](/device-access/android/root-magisk/) (GUI or terminal) ·
  [Autonomous script](/device-access/android/script/) ·
  [Recover a bricked device](/device-access/android/recover/) ·
  [Verify artifacts](/device-access/android/verify/).
- **[iOS](/device-access/ios/)** - jailbreak a supported iPhone/iPad. The tool
  depends on your chip: **A8-A11** (iPhone 6s/7/8/X, iPad 5/6/7) use
  **[palera1n](/device-access/ios/palera1n/)** (checkm8 - works on **any** iOS
  incl. 17/18); **A12+ on iOS ≤ 17.3.1** use **Dopamine**
  ([Download](/device-access/ios/download/) ·
  [Install](/device-access/ios/install/) ·
  [Run the jailbreak](/device-access/ios/run/)). Both end at
  [Verify artifacts](/device-access/ios/verify/).

Not sure you need root/jailbreak? You often don't: an Android **debuggable
build** exposes the app sandbox via `run-as`, an iOS **unencrypted backup**
reaches app-sandbox files, and the **Simulator** container is just a folder on
your Mac. Root/jailbreak is only required for the deepest surfaces (release-build
sandbox, live Keychain dump, runtime instrumentation).
