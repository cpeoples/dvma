Install DVMA on a physical iPhone. Both flows drive Xcode's build + signing under the hood and inject the DVMA flavor via `--dart-define-from-file` (the Simulator needs no signing, see [Build & Flavors](/getting-started/build-and-flavors/)).

<details>
<summary><strong>Install on a physical iPhone (macOS + Xcode)</strong></summary>

End-to-end, from a fresh clone to the app running on a plugged-in iPhone.
`flutter run`/`flutter install` drive Xcode's build + signing under the hood and
inject the DVMA flavor via `--dart-define-from-file`, so they're the correct
entry point (a bare Xcode build won't wire the flavor).

0. Prereqs (one-time): `flutter doctor` green for iOS (full Xcode + CocoaPods),
   iPhone Developer Mode ON (Settings ▸ Privacy & Security) and trusted over USB,
   and your Team ID set once (see [Finding your Team ID](/getting-started/prerequisites/#ios-device-physical)). Then clone and
   generate.

   ```sh
   cp ios/Flutter/Signing.xcconfig.example ios/Flutter/Signing.xcconfig
   # edit Signing.xcconfig -> DEVELOPMENT_TEAM = <your 10-char Team ID>
   git clone https://github.com/<your-org>/dvma.git
   cd dvma
   flutter pub get
   dart run tool/generate.dart          # (re)generate registry + router
   ```

1. Find your device id.

   ```sh
   flutter devices                      # copy the iOS device id (a long hash)
   ```

2. Build + sign + install + launch (hot reload attached) in one step…

   ```sh
   flutter run -d <device-id> --dart-define-from-file=config/flavors/full.json
   ```

   …or install only (build + sign + deploy, then detach)…

   ```sh
   flutter install -d <device-id> --dart-define-from-file=config/flavors/full.json
   ```

   …or build the `.app`/IPA and open Xcode to Run manually.

   ```sh
   flutter build ios --release --dart-define-from-file=config/flavors/full.json
   open ios/Runner.xcworkspace          # then hit Run (always the .xcworkspace)
   ```

Notes:

- iOS requires a signing team; unsigned builds won't install on a device (the
  **Simulator needs no signing**, so you can skip `Signing.xcconfig` there).
- A **free** Apple ID provisioning profile expires after **7 days**, re-deploy
  weekly. A paid Apple Developer account lasts a year.
- If you see the stock **"Flutter Demo Home Page"** counter instead of DVMA, see
  the [`--config-only` fix](/getting-started/prerequisites/#ios-device-physical), it means a stale
  `Generated.xcconfig` pointed the build at the wrong project.

</details>

<br/>

<details>
<summary><strong>Terminal-only iOS install (no Xcode GUI), <code>ideviceinstaller</code> / <code>ios-deploy</code> / <code>applesign</code></strong></summary>

`flutter run`/`install` already drive signing headlessly, so the *simplest*
GUI-free path is just `flutter build ios` + a CLI installer. You still need a
one-time signing identity (a free Apple ID added in Xcode → Settings → Accounts,
or an existing dev cert in your login keychain), Apple has **no** way to install
an unsigned app on a non-jailbroken device.

1. Install the CLI tools once.

   ```sh
   brew install libimobiledevice ideviceinstaller ios-deploy
   ```

2. Build a device `.app` with the DVMA flavor wired in (drives the Xcode
   toolchain, no GUI). Add `--config-only` first if you hit the
   stale-`Generated.xcconfig` issue.

   ```sh
   flutter build ios --release --dart-define-from-file=config/flavors/full.json
   ```

3. Install it to the attached device.

   ```sh
   APP="build/ios/iphoneos/Runner.app"
   idevice_id -l                                  # list attached device UDIDs
   ideviceinstaller install "$APP"                # libimobiledevice ≥1.2.0 subcommand
   #   older ideviceinstaller (<1.2.0) used:  ideviceinstaller -i "$APP"
   # or, with ios-deploy (also launches + streams logs):
   ios-deploy --bundle "$APP" --justlaunch --debug
   ```

If you instead have a **prebuilt `.ipa` signed for a different team** (e.g. from
CI) and need to re-sign it for your device without opening Xcode, the easiest
path is **[`applesign`](https://github.com/nowsecure/node-applesign)** (NowSecure's
re-signing CLI). It builds the mach-O dependency list and signs every nested
framework **in the correct order automatically**, which is the fragile part of
doing it by hand for a Flutter app (`App.framework`, `Flutter.framework`, plugin
frameworks):

```sh
npm i -g applesign
applesign -L                                    # list local codesign identities
applesign -c -m your.mobileprovision App.ipa    # -c clones entitlements from the profile
ideviceinstaller install App-resigned.ipa       # (or: ios-deploy -b App-resigned.ipa)
```

> **Frida without a jailbreak.** `applesign -I frida.dylib App.ipa` *inserts* a
> dylib into the main executable, so you can Frida-introspect DVMA on a
> **non-jailbroken** device, the sideload-based alternative to the Frida-gadget
> path (see the Root & Jailbreak page for the jailbreak route).

Or do it **by hand** with `codesign` (no Node), the same steps `applesign`
automates. A Flutter app's **nested frameworks** must each be signed
**depth-first** (inner bundles before the outer `.app`), or it installs but
won't launch:

1. Extract entitlements from a provisioning profile that includes your device's
   UDID.

   ```sh
   security cms -D -i your.mobileprovision > profile.plist
   /usr/libexec/PlistBuddy -x -c 'Print :Entitlements' profile.plist > entitlements.plist
   ```

2. Unzip the `.ipa` and swap in your provisioning profile.

   ```sh
   unzip -q App.ipa -d resign && APP="resign/Payload/Runner.app"
   cp your.mobileprovision "$APP/embedded.mobileprovision"
   rm -rf "$APP/_CodeSignature"
   ```

3. Sign the **inner** bundles first (Flutter ships `App`/`Flutter` + plugin
   frameworks).

   ```sh
   IDENT="Apple Development: Your Name (TEAMID)"   # security find-identity -v -p codesigning
   for f in "$APP"/Frameworks/*.framework "$APP"/Frameworks/*.dylib; do
     codesign -f -s "$IDENT" --entitlements entitlements.plist "$f"
   done
   ```

4. Sign the app bundle itself, then repackage and install.

   ```sh
   codesign -f -s "$IDENT" --entitlements entitlements.plist "$APP"
   (cd resign && zip -qr ../App-resigned.ipa Payload)
   ideviceinstaller install App-resigned.ipa
   ```

</details>

<br/>

<details>
<summary><strong>⚠️ Install fails with <code>0xe8008018</code> ("identity … no longer valid") - the revoked-cert wall</strong></summary>

This is the single most confusing on-device failure, and **no command-line tool
can fix it** - only Xcode's GUI can. You'll see it from `flutter run`,
`flutter install`, `ideviceinstaller`, `ios-deploy`, *and* `xcodebuild` even when
the build clearly **succeeds** and signs:

```text
ERROR: Install failed. Got error "ApplicationVerificationFailed" with code
0xe8008018: Failed to verify code signature of …/Runner.app :
0xe8008018 (The identity used to sign the executable is no longer valid.)
```

**What it actually means.** The signing certificate in your keychain *looks*
valid locally (`security find-identity -v` lists it, its `notAfter` date is a
year out), but the **device checks Apple's servers**, which have that certificate
marked **revoked**. Free "Personal Team" certs get revoked routinely - e.g. you
regenerated one, hit the **2-active-certificate limit**, added the same Apple ID
on another Mac, or a previous cert was used to sign something else (that's why
this often appears right after signing an unrelated app like a jailbreak IPA).
Local tools can't re-mint a cert; they just keep signing with the dead one.

**Why CLI can't fix it, and Xcode can.** Regenerating a valid certificate
requires an authenticated round-trip to Apple's Developer service. Xcode's
**automatic signing** does exactly that (revoke-and-regenerate); the CLI tools
only *use* whatever's already in the keychain.

**The fix (≈2 minutes, do it once):**

1. **Open the workspace** (always the `.xcworkspace`, never `.xcodeproj`):

   ```sh
   open ios/Runner.xcworkspace
   ```

2. Select the blue **Runner** project → under **TARGETS** pick **Runner** → open
   the **Signing & Capabilities** tab.

3. Tick **Automatically manage signing**, then pick your **Team**. A **free**
   account shows as **"Your Name (Personal Team)"** - that's fine and expected;
   it does **not** need to match a paid Team ID you may have used on the CLI. (In
   fact a *free/paid mismatch* between Xcode and your CLI `DEVELOPMENT_TEAM` is a
   common cause of this error - let Xcode pick the team here and it becomes the
   source of truth.)

4. **Force provisioning to regenerate.** Watch the Signing pane:
   - If Xcode shows a yellow/red banner with a **"Fix Issue"** (or **"Try
     Again"** / **"Revoke and regenerate"**) button → **click it** and sign in
     with your Apple ID. **This is the step that mints a fresh, valid cert.**
   - If there's no banner but the error persists, force it by hand: toggle
     **Automatically manage signing** **off then on again**, or switch **Team**
     to *None* and back to your team. Either forces Xcode to re-request a profile
     - certificate from Apple.
   - When healthy, the pane shows **Provisioning Profile: Xcode Managed Profile**
     and **Signing Certificate: Apple Development: Your Name** with **no red
     errors**.

   > **STUCK: "You already have a current Development certificate or a pending
   > certificate request"?** This is the deadlock a **free** account hits, and it's
   > the most common reason the fix above doesn't "just work." A free Personal Team
   > allows only **2** Apple Development certificates, and you're maxed out - so
   > **"Fix Issue"** and **Manage Certificates → `+` → Apple Development** both
   > refuse to make a new one. You must **delete the bad cert first**, then create a
   > fresh one. Here's the exact, reliable way:
   >
   > **a. See what you have.** In **Xcode → Settings → Accounts → your account →
   > Manage Certificates** you'll typically see two rows - e.g. one greyed-out
   > *"… (Not in Keychain)"* (its private key isn't on this Mac, so it's useless
   > here) and one that *is* in your keychain (the one you're signing with, and the
   > one the device rejects). Both slots are taken.
   >
   > **b. Delete the in-keychain cert from Keychain Access - reliably, via CLI.**
   > The Keychain Access GUI often *won't* delete it (multi-select quirk, or it
   > leaves the private key behind). Do it from the terminal instead - this removes
   > the certificate **and** its private key in one shot:
   >
   > ```sh
   > # 1) Find the bad identity's 40-char SHA-1 hash:
   > security find-identity -v -p codesigning
   > #    e.g.  1) 35789EE7…  "Apple Development: Your Name (XXXXXXXXXX)"
   >
   > # 2) Delete it by that hash from the LOGIN keychain (cert + key together):
   > security delete-certificate -Z <THAT_SHA1_HASH> \
   >   "$HOME/Library/Keychains/login.keychain-db"
   >
   > # 3) Confirm it's gone - must print "0 valid identities found":
   > security find-identity -v -p codesigning
   > ```
   >
   > > The cert lives in the **login** keychain (select **login**, *not* **iCloud**,
   > > in Keychain Access's sidebar). `delete-certificate -Z <hash>` on a personal
   > > identity removes the matching private key with it.
   >
   > **c. Free the slot on Apple's side too (if `+` still refuses).** Deleting
   > locally frees your keychain, but Apple may still count the cert against your
   > 2-cert limit. Revoke it in the browser:
   > **[developer.apple.com/account → Certificates](https://developer.apple.com/account/resources/certificates/list)**
   > → select the stale **Apple Development** cert(s) → **Revoke**.
   >
   > **d. Mint a fresh one.** Back in **Manage Certificates**, click **`+` → Apple
   > Development**. With a slot free and the keychain clean, it now creates a
   > **brand-new cert with its private key in this keychain** - no error. Click
   > **Done**, return to **Signing & Capabilities**, and continue to step 5.

5. **Pick the device** in the toolbar (e.g. *"Bob's iPhone"*) and press ▶︎
   **Run** (⌘R). Xcode registers the device, installs, and launches. On the
   **phone**, if prompted that the developer is untrusted:
   **Settings → General → VPN & Device Management → Apple Development: Your
   Name → Trust**, then press ▶︎ again.

**After Xcode has minted the good cert once, the CLI works again.** From then on
`flutter run` / `flutter install` / `ideviceinstaller` all succeed, because they
reuse the now-valid certificate + Xcode-managed profile:

```sh
flutter install -d <device-id> --dart-define-from-file=config/flavors/full.json
```

**Clearing stale device profiles (optional, if it still balks).** A device can
cache old profiles bound to the dead cert. List and remove them, then reinstall:

```sh
ideviceprovision list                     # shows profiles installed ON the device
ideviceprovision remove <profile-uuid>    # remove any stale com.dvma / test ones
```

> **Why not just use the CLI end-to-end?** You can, *once a valid cert exists*.
> The very first provisioning of a fresh/free account - or any time Apple revokes
> the cert - must go through Xcode's GUI to regenerate it. There is no supported
> headless equivalent for minting an Apple Development certificate.
</details>
