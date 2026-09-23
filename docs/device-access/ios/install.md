**Sideloading** = installing an `.ipa` **without the App Store**, by re-signing
it with a code-signing identity the device trusts. A **free Apple Account** signs
for **7 days** (re-install when it expires); [**TrollStore**](https://trollstore.com/)
signs **permanently** but only exists on older exploitable versions (roughly iOS
14.0 - 16.6.1), so on iOS 17 you'll use one of the free-Apple-Account tools below.

> **Prerequisites:** you've confirmed your device qualifies (Step 0 on the
> [iOS overview](/device-access/ios/)) and downloaded the right file (`.ipa` or `.tipa`, see
> [Download Dopamine](/device-access/ios/download/)).

**Pick ONE installer**, then **expand its box below** and follow it top to bottom.
**Each box is fully self-contained (its own Step 0 → last step)** - you only need
the one you pick.

| Use this | If you… | Needs a computer? |
| --- | --- | --- |
| **Sideloadly** | just want the simplest one-shot install | Yes (Mac/PC), only at install time |
| **AltStore** | want the signature auto-refreshed | Yes, running on the same Wi-Fi |
| **SideStore** | want no computer after first setup | Only for first pairing |
| **TrollStore** | *already* have it (≤ iOS 16.6.1) → permanent, no 7-day expiry | No |
| **Provisioning profile / cert (`zsign` / `applesign`)** | already have (or can make) a dev cert and want a headless/scriptable path | Yes (CLI) |

<details>
<summary><strong>Sideloadly - simplest one-shot (Mac/PC)</strong></summary>

Needs a Mac/PC only at install time ([sideloadly.io](https://sideloadly.io/)).

0. **Confirm the device qualifies** (Step 0 on the [overview](/device-access/ios/)): a recent
   iPhone must be on **iOS ≤ 17.3.1**. If not, stop - Dopamine can't jailbreak it.
1. **Have `Dopamine.ipa`** on the computer (from [Download Dopamine](/device-access/ios/download/)).
2. **Make a throwaway Apple Account** at [account.apple.com](https://account.apple.com/) - do **not** use your real one.
3. On the computer, **download + install Sideloadly**, then open it.
4. **Connect the iPhone by USB.** Sideloadly shows it at the top; on the phone tap
   **Trust This Computer** if asked.
5. **Drag `Dopamine.ipa`** onto the Sideloadly window (or click the app-file box and select it).
6. In **Apple account**, enter your **throwaway** Apple Account, then click **Start**;
   enter the password (and an app-specific password if 2FA prompts).
7. Wait for Sideloadly to report **Done** - **Dopamine** is now on the Home screen.
8. On the phone: **Settings → General → VPN & Device Management →** tap your
   Apple-Account developer app **→ Trust**.
9. **Open Dopamine** to confirm it launches, then go to **[Run the jailbreak](/device-access/ios/run/)**.
10. When the **7-day** signature expires, just repeat steps 4-8 to re-install.

</details>

<details>
<summary><strong>AltStore / AltServer - auto-refreshing (computer on same Wi-Fi)</strong></summary>

Auto-refreshes the signature ([altstore.io](https://altstore.io/)); a computer must stay on the same Wi-Fi.

0. **Confirm the device qualifies** (Step 0 on the [overview](/device-access/ios/)): iOS **≤ 17.3.1** on a recent iPhone.
1. **Have `Dopamine.ipa`** available (from [Download Dopamine](/device-access/ios/download/)).
2. **Make a throwaway Apple Account** at [account.apple.com](https://account.apple.com/) (not your real one).
3. On the computer, **install AltServer** and run it (macOS Mail plug-in or the standalone app).
4. **Connect the phone by USB;** tap **Trust This Computer** on the phone if asked.
5. From AltServer's menu-bar/tray icon → **Install AltStore →** pick your device;
   sign in with the **throwaway** Apple Account. This puts the **AltStore** app on the phone.
6. On the phone: **Settings → General → VPN & Device Management →** **trust** your
   Apple-Account developer app.
7. **Get `Dopamine.ipa` onto the phone** (AirDrop it, or save it into the Files app).
8. Open **AltStore → My Apps → “+” (top-left) →** select **`Dopamine.ipa`**.
   AltStore signs + installs it - **Dopamine** appears on the Home screen.
9. **Keep AltServer running on the same Wi-Fi** so it auto-refreshes the 7-day signature.
10. **Open Dopamine** to confirm it launches, then go to **[Run the jailbreak](/device-access/ios/run/)**.

</details>

<details>
<summary><strong>SideStore - no computer after setup</strong></summary>

On-device signature renewal ([sidestore.io](https://sidestore.io/)); a computer is only needed for first pairing.

0. **Confirm the device qualifies** (Step 0 on the [overview](/device-access/ios/)): iOS **≤ 17.3.1** on a recent iPhone.
1. **Have `Dopamine.ipa`** ready (from [Download Dopamine](/device-access/ios/download/)).
2. **Make a throwaway Apple Account** at [account.apple.com](https://account.apple.com/).
3. Do SideStore's **one-time pairing** from a computer following the official
   installer on its site (installs SideStore + a pairing file), signing in with
   the throwaway Apple Account.
4. On the phone, when prompted, **enable the SideStore VPN/loopback** (this is how
   it re-signs on-device) and trust the profile under **Settings → General → VPN &
   Device Management** if asked.
5. **Get `Dopamine.ipa` onto the phone** (AirDrop or the Files app).
6. Open **SideStore → My Apps → “+” →** select **`Dopamine.ipa`** → install.
7. Wait for it to finish - **Dopamine** is on the Home screen; SideStore renews the
   signature on-device afterward.
8. **Open Dopamine** to confirm it launches, then go to **[Run the jailbreak](/device-access/ios/run/)**.

</details>

<details>
<summary><strong>TrollStore - permanent, no 7-day expiry (≤ iOS 16.6.1 only)</strong></summary>

**What it is:** TrollStore is **not a jailbreak** - it's a utility that
**permanently signs and installs** `.tipa` apps using a CoreTrust signing bug, so
an app you install through it **never expires** and needs **no computer and no
Apple Account** afterward. That's why it's the nicest way to install `Dopamine.tipa`
*if your device supports it*.

**The catch - how you "get" TrollStore:** you don't just download-and-sideload
TrollStore itself; you run a small **installer app** once, which then installs
TrollStore onto the device:

- **[TrollInstallerX](https://github.com/alfiecg24/TrollInstallerX)** - the main
  installer; you sideload *it* (via Sideloadly/AltStore, so a computer once), open
  it, and tap **Install TrollStore**.
- **TrollHelperOTA** - a no-computer route on older iOS (≈ 14.0 - 15.6.1).

**Supported iOS:** roughly **iOS 14.0 - 16.6.1** (arm64 & arm64e). **Not**
supported on **16.7.x** (except 16.7 RC) or **17.0.1+** - if you're on iOS 17,
use **Sideloadly / AltStore / SideStore** above instead. Follow the exact
device/version route in the community guide:
<https://ios.cfw.guide/installing-trollstore/>.

Steps:

0. **Confirm this applies:** device on **iOS 14.0 - 16.6.1** (see the guide's
   table for your exact chip/version). On iOS 17 → use another installer above.
1. **Get TrollStore onto the device** (one time): install **TrollInstallerX**
   (sideload it with Sideloadly/AltStore, enable **Developer Mode** on iOS 16+ if
   asked, open it, tap **Install TrollStore**, and pick a persistence-helper app
   like *Tips* when prompted) - or use **TrollHelperOTA** on older iOS. Full
   per-device steps: <https://ios.cfw.guide/installing-trollstore/>.
2. On the [Download Dopamine](/device-access/ios/download/) page, grab **`Dopamine.tipa`** (the
   TrollStore package), **not** the `.ipa`.
3. **Get `Dopamine.tipa` onto the phone** (AirDrop, or save it into the Files app).
4. Open **TrollStore → “+” →** select **`Dopamine.tipa`** → **Install**.
5. Done - the signature is **permanent**: no Apple Account, no 7-day expiry, no trust step.
6. **Open Dopamine** to confirm it launches, then go to **[Run the jailbreak](/device-access/ios/run/)**.

</details>

<details>
<summary><strong>Provisioning profile / signing cert (CLI)</strong></summary>

Sign the `.ipa` yourself and install it headlessly - no GUI installer. This is the
right route if you have (or can make) an **Apple Development signing identity**. It
needs **two** things most guides gloss over: a **signing certificate + private key**
(the "identity") *and* a **provisioning profile** (`.mobileprovision`) that includes
**your device's UDID** and grants **`get-task-allow`**. The steps below show how to
obtain *both* from scratch, then sign with either signer.

> ### ⚡ Quick path (copy/paste) - the known-good sequence
>
> If you already have an **Apple Development** identity in your keychain (check with
> `security find-identity -v -p codesigning`) and Xcode has downloaded your
> provisioning profiles, this is the **entire working flow**, start to finish. Run it
> from the folder containing `Dopamine.ipa`, with the iPhone plugged in and trusted.
> The numbered sections below explain each piece if a step needs adjusting.
>
> ```bash
> # (1) Your signing identity's 40-char SHA-1 hash (the hex before the quotes).
> IDENTITY_SHA1=$(security find-identity -v -p codesigning \
>   | awk '/Apple Development/ {print $2; exit}')
> echo "IDENTITY_SHA1=$IDENTITY_SHA1"          # must print a 40-char hex string
>
> # (2) Auto-pick the right provisioning profile + the bundle id to sign as.
> DIR="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
> [ -d "$DIR" ] || DIR="$HOME/Library/MobileDevice/Provisioning Profiles"
> UDID=$(idevice_id -l)
> TEAM=$(security find-certificate -c "Apple Development" -p 2>/dev/null \
>   | openssl x509 -noout -subject 2>/dev/null | grep -oE 'OU=[A-Z0-9]{10}' | cut -d= -f2 | head -1)
> PREFER_APP="${PREFER_APP:-com.dvma}"
> PROF=""; PROF_APPID=""
> for f in "$DIR"/*.mobileprovision; do
>   plist=$(security cms -D -i "$f" 2>/dev/null)
>   appid=$(plutil -extract Entitlements.application-identifier raw -o - - <<<"$plist" 2>/dev/null)
>   gta=$(plutil -extract Entitlements.get-task-allow raw -o - - <<<"$plist" 2>/dev/null)
>   dev=no; grep -qi "$UDID" <<<"$plist" && dev=YES
>   bid="${appid#*.}"
>   case "$appid" in "$TEAM".*) ok_team=1 ;; *) ok_team=0 ;; esac
>   if [ "$dev" = YES ] && [ "$gta" = true ] && [ "$ok_team" = 1 ] \
>      && [ "$bid" != "*" ] && ! grep -qi xctrunner <<<"$bid"; then
>     if [ "$bid" = "$PREFER_APP" ] || [ -z "$PROF" ]; then PROF="$f"; PROF_APPID="$appid"; fi
>   fi
> done
> BUNDLE_ID="${PROF_APPID#*.}"
> echo "PROF=$PROF"; echo "BUNDLE_ID=$BUNDLE_ID"   # both must be non-empty
>
> # (3) Sign - the -a and -v flags are REQUIRED (see below), not optional.
> npx applesign -i "$IDENTITY_SHA1" -m "$PROF" -b "$BUNDLE_ID" -c -a -v \
>   -o Dopamine-signed.ipa Dopamine.ipa
>
> # (4) Install the SIGNED file (never the raw Dopamine.ipa).
> ideviceinstaller install Dopamine-signed.ipa
> ```
>
> **The four things a first-timer gets wrong - and this sequence gets right:**
>
> 1. **`-a` (`--all`)** re-signs Dopamine's **nested frameworks** (e.g.
>    `badRecovery.framework`). Without it the install dies with
>    `0xe800801c (No code signature found)` on a framework. **This is mandatory.**
> 2. **`-b "$BUNDLE_ID"`** signs the app *as the profile's App ID* (e.g. `com.dvma`),
>    not Dopamine's own `com.opa334.Dopamine`. Skip it and you get
>    `0xe8008015 (A valid provisioning profile … was not found)`.
> 3. The profile picker **prefers `com.dvma` on your own team** and skips signer
>    *sample* profiles (like `com.testing.testytest` / `com.nowsecure.testapp`) - a
>    wrong pick makes the install go out under a bogus bundle id.
> 4. **Install `Dopamine-signed.ipa`, not `Dopamine.ipa`.** The raw download is
>    unsigned → `0xe800801c (No code signature found)` on the app itself.
>
> Full per-step details, alternatives (`zsign` + `.p12`), and every error message
> follow.

**0. Confirm the device qualifies** (Step 0 on the [overview](/device-access/ios/)): iOS **≤ 17.3.1**
on a recent iPhone (A14+); older chips have wider ranges. Have `Dopamine.ipa`
(from [Download Dopamine](/device-access/ios/download/)).

**1. Check what signing identity you already have.** A "codesigning identity" is a
certificate **plus its private key** in your keychain - that's exactly what a `.p12`
bundles into one file. List them:

```bash
security find-identity -v -p codesigning
# e.g.  1) 35789EE7…  "Apple Development: Your Name (PD3MNN5HFN)"
#           └─ this 40-char hex is your IDENTITY_SHA1 ─┘  └─ just a label ─┘
```

The **40-character hex string before the quotes** is your `IDENTITY_SHA1` - it's what
the signer needs (`applesign -i …`). Capture it into a variable so you never have to
copy it by hand:

```bash
IDENTITY_SHA1=$(security find-identity -v -p codesigning \
  | awk '/Apple Development/ {print $2; exit}')
echo "IDENTITY_SHA1=$IDENTITY_SHA1"     # 40-char hex; if empty, you have no identity yet
```

- **Got an `Apple Development: …` line?** You already have a usable identity - skip to
  step 3 (profile). **Paid** Apple Developer certs last **1 year**; **free** Apple
  Account certs last **7 days** (you re-sign weekly).
- **Nothing listed?** Create one for free in **Xcode → Settings → Accounts →** add your
  Apple Account **→ Manage Certificates → “+” → Apple Development**. That drops the
  cert + private key into your login keychain.

**2. (Optional) Export the identity to a portable `.p12`.** You only need this if you'll
sign with `zsign`, move the identity to another machine/CI, or just prefer a file.
There are three ways to produce one:

- **Keychain Access (the normal macOS way).** Keychain Access → **login → My
  Certificates →** expand your **“Apple Development: …”** row (confirm a **private
  key** is nested under it - no key = can't sign) → right-click → **Export →**save as
  `dvma-dev.p12`, set a password. **This must be done in the GUI:** macOS blocks
  non-interactive private-key export by design, so there's no fully-headless
  equivalent. (If you'd rather avoid the `.p12` entirely, use the **applesign**
  variant below, which signs straight from the keychain by identity hash.)
- **`security export` (CLI, only if the key's ACL already allows export):**

  ```bash
  security export -k ~/Library/Keychains/login.keychain-db \
    -t identities -f pkcs12 -P '<p12-password>' -o dvma-dev.p12
  # Usually still pops a one-time keychain "Allow" prompt for the private key.
  ```

- **`openssl` (only if you already have separate PEM cert + key files, e.g. from CI):**

  ```bash
  openssl pkcs12 -export -inkey key.pem -in cert.pem -out dvma-dev.p12
  ```

**3. Get a provisioning profile that includes your device.** The signature is only
valid if a profile lists **your device's UDID** and authorizes the app's
entitlements. Two ways:

- **Let Xcode mint it (easiest - also registers the UDID).** Point `xcodebuild` at any
  Xcode project with **automatic signing** and your team, targeting the connected
  device. Xcode registers the UDID and writes an `embedded.mobileprovision` into the
  built `.app`:

  ```bash
  UDID=$(idevice_id -l)                      # the connected device
  xcodebuild -project ios/Runner.xcodeproj -scheme Runner \
    -destination "id=$UDID" \
    -allowProvisioningUpdates -allowProvisioningDeviceRegistration \
    DEVELOPMENT_TEAM=<YOUR_TEAM_ID> build-for-testing
  # Grab the profile it produced (bundle id can differ from Dopamine's - fine,
  # the signer rewrites it):
  cp ~/Library/Developer/Xcode/DerivedData/Runner-*/Build/Products/*-iphoneos/*.app/embedded.mobileprovision \
     ./dvma-dev.mobileprovision
  ```

  > The build itself doesn't need to *finish* - the `embedded.mobileprovision`
  > appears as soon as Xcode resolves signing (early in the build), so you can stop it
  > once the file exists.

- **Or download one** from [developer.apple.com](https://developer.apple.com/account/resources/profiles/list)
  (register the device's UDID under **Devices** first, create a **Development** profile
  including it, download the `.mobileprovision`).

- **Or download the ones Xcode already made for you (GUI, no build).** If Xcode has
  ever signed a project for your team, it has profiles ready to fetch:
  **Xcode → Settings → Accounts → select your Apple Account + team → Download Manual
  Profiles**. They land in one of:

  ```bash
  ~/Library/Developer/Xcode/UserData/Provisioning\ Profiles/   # Xcode 16+
  ~/Library/MobileDevice/Provisioning\ Profiles/               # older Xcode
  ```

  There are usually several - **pick a plain app-level Development profile** (e.g.
  `iOS Team Provisioning Profile: com.dvma`) that has `get-task-allow: true` and
  includes your device; **skip** any `*.xctrunner` / `*RunnerUITests*` profile (those
  are test-runner profiles, not for a normal app). List and identify them:

  ```bash
  DIR="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
  [ -d "$DIR" ] || DIR="$HOME/Library/MobileDevice/Provisioning Profiles"   # older Xcode
  UDID=$(idevice_id -l)

  # Your TEAM ID = the OU field of your signing cert (positive filter - a profile
  # is only usable if it's on YOUR team). Grab it from the identity you'll sign with.
  TEAM=$(security find-certificate -c "Apple Development" -p 2>/dev/null \
    | openssl x509 -noout -subject 2>/dev/null | grep -oE 'OU=[A-Z0-9]{10}' | cut -d= -f2 | head -1)
  # The bundle id you WANT to sign as - a real app id you control. Default com.dvma;
  # override if your profiles use a different one (e.g. PREFER_APP=com.example.app).
  PREFER_APP="${PREFER_APP:-com.dvma}"
  echo "team=$TEAM  prefer-app=$PREFER_APP"

  PROF=""; PROF_APPID=""                    # chosen profile path + its App ID
  for f in "$DIR"/*.mobileprovision; do
    plist=$(security cms -D -i "$f" 2>/dev/null)                 # decode inline, no temp file
    nm=$(plutil -extract Name raw -o - - <<<"$plist" 2>/dev/null)
    appid=$(plutil -extract Entitlements.application-identifier raw -o - - <<<"$plist" 2>/dev/null)
    gta=$(plutil -extract Entitlements.get-task-allow raw -o - - <<<"$plist" 2>/dev/null)
    dev=no; grep -qi "$UDID" <<<"$plist" && dev=YES              # UDIDs are plain text
    bid="${appid#*.}"                                            # App ID minus team prefix
    printf '%s\n  Name: %s | app-id: %s | get-task-allow: %s | has-this-device: %s\n' \
      "$(basename "$f")" "$nm" "$appid" "$gta" "$dev"
    # POSITIVE match only: on YOUR team, lists THIS device, debuggable, a concrete
    # app id (no wildcard/xctrunner). No blocklist of specific sample names.
    case "$appid" in "$TEAM".*) ok_team=1 ;; *) ok_team=0 ;; esac
    if [ "$dev" = YES ] && [ "$gta" = true ] && [ "$ok_team" = 1 ] \
       && [ "$bid" != "*" ] && ! grep -qi xctrunner <<<"$bid"; then
      # Prefer the app id you actually want; otherwise take the first valid one.
      if [ "$bid" = "$PREFER_APP" ] || [ -z "$PROF" ]; then PROF="$f"; PROF_APPID="$appid"; fi
    fi
  done
  BUNDLE_ID="${PROF_APPID#*.}"              # e.g. TEAMID.com.dvma -> com.dvma
  echo "SELECTED PROF=$PROF"
  echo "SIGN AS BUNDLE_ID=$BUNDLE_ID"      # <- pass this to the signer's -b flag
  ```

  That `PROF` is what you hand the signer via `-m "$PROF"`. **How this picks the
  right one - positively, not by blocklisting names:** it keeps only profiles that
  are **on your team** (`$TEAM`, read from your signing cert), **list this device**,
  are **debuggable** (`get-task-allow`), and target a **concrete app id** (no `*`
  wildcard, no `*.xctrunner` test-runner). Among those it **prefers the app id you
  actually control** (`PREFER_APP`, default `com.dvma`) - so a signer's bundled
  *sample* profile (e.g. applesign's `com.nowsecure.testapp`) is simply never
  preferred, without hardcoding its name. Override `PREFER_APP=<your.bundle.id>` if
  your profiles use a different one.

  **`BUNDLE_ID` matters:** a profile authorizes ONE App ID (e.g. `TEAMID.com.dvma`),
  but Dopamine's own bundle id is `com.opa334.Dopamine` - a mismatch makes iOS reject
  the install with `0xe8008015 (A valid provisioning profile … was not found)`. So you
  must **rewrite Dopamine's bundle id to match the profile** during signing (the
  `-b "$BUNDLE_ID"` in step 4). If `SELECTED PROF=` is empty, no usable profile lists
  this device - register the UDID (Xcode with the device connected, then **Download
  Manual Profiles**) and re-run the loop.

  **Sanity-check the chosen profile** contains your device + `get-task-allow`
  (decodes inline - no temp file):

  ```bash
  plist=$(security cms -D -i "$PROF")
  grep -c "$UDID" <<<"$plist"                                        # >=1 (device listed)
  plutil -extract Entitlements.get-task-allow raw -o - - <<<"$plist" # true
  plutil -extract ExpirationDate raw -o - - <<<"$plist"
  ```

**4. Sign the `.ipa`.** Pick **one** signer. Both re-sign the app with your identity and
**clone the profile's entitlements** onto it (that's the `-c` / entitlements step -
required so iOS accepts the app):

- **`zsign` (uses the `.p12` from step 2):**

  ```bash
  brew install zsign
  # A .p12 already bundles the cert + private key, so no separate -c is needed.
  # -b rewrites Dopamine's bundle id to match the profile's App ID (required).
  zsign -k dvma-dev.p12 -p '<p12-password>' -m "$PROF" -b "$BUNDLE_ID" \
    -o Dopamine-signed.ipa Dopamine.ipa
  # (If instead you have separate PEM files, pass the cert with -c:
  #  zsign -k key.pem -c cert.pem -m "$PROF" -b "$BUNDLE_ID" -o out.ipa Dopamine.ipa)
  ```

- **`applesign` (signs straight from the keychain - no `.p12` needed):**

  ```bash
  # Install (npm global). If your ~/.npmrc points at a PRIVATE registry (corp
  # Artifactory, etc.), force the public one so the install doesn't try to auth:
  npm install -g applesign --registry=https://registry.npmjs.org/
  # If `applesign` still isn't on your PATH after -g (common with nvm/corepack),
  # just call it via npx instead - same tool, no PATH fiddling:
  #   npx applesign ...

  applesign -L                                   # list identity hashes (or: npx applesign -L)
  # -i is your IDENTITY_SHA1 from step 1 (the 40-char hex).
  # -b sets the bundle id to the profile's App ID; -c clones profile entitlements.
  # -a re-signs ALL nested binaries (Dopamine bundles frameworks like
  #    badRecovery.framework - every nested Mach-O MUST be signed or the install
  #    fails with 0xe800801c "No code signature found" on that framework).
  # -v verifies every signed file at the end so you catch a straggler before install.
  # Use `npx applesign` if the bare `applesign` command isn't found (see note below).
  npx applesign -i "$IDENTITY_SHA1" -m "$PROF" -b "$BUNDLE_ID" -c -a -v \
    -o Dopamine-signed.ipa Dopamine.ipa
  # (applesign can also take a .p12:  -k dvma-dev.p12 -P '<password>')
  ```

  > **Trouble installing or running `applesign`?** Two common snags:
  >
  > - **`npm install -g` fails with an auth/`ENEEDAUTH`/`could not locate` error**
  >   even though applesign is public - your `~/.npmrc` points at a **private
  >   registry** (corporate Artifactory, etc.), so npm tries to auth against it.
  >   Force the public registry for just this install:
  >
  >   ```bash
  >   npm install -g applesign --registry=https://registry.npmjs.org/
  >   ```
  >
  > - **`zsh: command not found: applesign` after a successful `-g` install.** With
  >   **nvm/corepack** the global `bin` often isn't on your `PATH` (`ls "$(npm prefix
  >   -g)/bin"` shows only `node/npm/npx`, no `applesign`). Don't fight the PATH -
  >   just run it through **`npx`**, which resolves+runs it regardless:
  >
  >   ```bash
  >   npx applesign -i "$IDENTITY_SHA1" -m "$PROF" -b "$BUNDLE_ID" -c -a -v \
  >     -o Dopamine-signed.ipa Dopamine.ipa
  >   ```
  >
  >   (`npx` will offer to fetch `applesign@latest` the first time - accept it.)
  >   Do **not** try `node applesign …` - that looks for a local file, not the
  >   installed CLI, and fails with `Cannot find module '…/applesign'`.

  > `0xe8008015 (A valid provisioning profile … was not found)`? The app's bundle id
  > doesn't match the profile's App ID. `-b "$BUNDLE_ID"` fixes it - sign the app *as*
  > the profile's app id (e.g. `com.dvma`), not Dopamine's own `com.opa334.Dopamine`.
  > Re-sign with `-b` and reinstall. Also make sure the selection above landed on a
  > real app profile on your team (it prefers `PREFER_APP`), not a signer's bundled
  > sample.

  > `0xe800801c (No code signature found)` on a **nested framework** (e.g.
  > `…/Payload/Dopamine.app/Frameworks/badRecovery.framework`)? You signed only the
  > main app binary and left its bundled frameworks unsigned - iOS requires **every**
  > nested Mach-O to be signed. Add **`-a` (`--all`)** so applesign re-signs all
  > nested binaries, and **`-v`** to verify before install:
  >
  > ```bash
  > npx applesign -i "$IDENTITY_SHA1" -m "$PROF" -b "$BUNDLE_ID" -c -a -v \
  >   -o Dopamine-signed.ipa Dopamine.ipa
  > ```
  >
  > (`zsign` re-signs nested frameworks by default, so this only bites `applesign`
  > runs that omitted `-a`.)

  > **macOS gotcha (App Management / provenance):** if `applesign` fails with
  > `EPERM … open '…/Payload/Dopamine.app/Dopamine'`, macOS is blocking your
  > (nvm/Homebrew) `node` from **reading** the app's Mach-O - Apple-signed tools like
  > `codesign` can read it but `node`/`cat` can't. Fix by granting **Full Disk Access**
  > to your terminal (**System Settings → Privacy & Security → Full Disk Access →** add
  > Terminal/iTerm), *or* just use the **`zsign` + `.p12`** path above (it doesn't do
  > the offending read). This is common on freshly-downloaded `.ipa`s.

**5. Connect the phone by USB** and tap **Trust This Computer** if asked
(`idevicepair validate` should say *SUCCESS*).

**6. Install the signed IPA - path depends on the iOS major version:**

  > **Install `Dopamine-signed.ipa`, NOT the raw `Dopamine.ipa`.** Installing the
  > unsigned download fails with:
>
  > ```text
  > ERROR: Install failed. Got error "ApplicationVerificationFailed" with code
  > 0xe800801c: Failed to verify code signature ... : 0xe800801c (No code
  > signature found.)
  > ```
>
  > That means you skipped step 4 (signing). iOS only runs code signed by an
  > identity + profile it trusts, so you must sign first, then install the
  > `-signed` file. *(The earlier `WARNING: could not locate iTunesMetadata.plist`
  > / `SC_Info/…sinf` lines are harmless - those only exist in App Store copies.)*

  ```bash
  # iOS 16 and below (e.g. iPhone X on 16.7.x): libimobiledevice does it directly.
  ideviceinstaller install Dopamine-signed.ipa
  ideviceinstaller list | grep -i dopamine        # confirm it's installed

  # iOS 17.0-17.3.1: developer services go through a root tunnel - start it first,
  # in its own terminal, and leave it running:
  sudo python3 -m pip install -U pymobiledevice3   # once
  sudo python3 -m pymobiledevice3 remote tunneld   # leave running
  pymobiledevice3 apps install Dopamine-signed.ipa
  pymobiledevice3 apps list | grep -i dopamine
  ```

  > **If install instead fails with a *device*/*provisioning* error** - e.g.
  > `0xe8008015 (A valid provisioning profile for this executable was not found)` -
  > the app's **bundle id doesn't match the profile's App ID** (fix: re-sign with
  > `-b "$BUNDLE_ID"`, step 4), or the profile simply doesn't list this device's
  > UDID. For the latter: connect the device, open the Xcode project once (or run
  > the `xcodebuild … -allowProvisioningDeviceRegistration` command in step 3) to
  > auto-register the UDID, **re-download Manual Profiles**, and re-sign.

**7. Trust the developer profile on the phone** (free/personal certs only):
   **Settings → General → VPN & Device Management →** tap your developer app **→ Trust**.
   *(Paid Apple Developer / enterprise certs are trusted automatically - skip.)* See the
   [Run the jailbreak](/device-access/ios/run/) page for the full trust + Developer-Mode details.

**8. Open Dopamine** to confirm it launches, then go to **[Run the jailbreak](/device-access/ios/run/)**.
   *(A **free** Apple-Account signature expires in **7 days** - re-run steps 4-7 to
   renew. A **paid** dev cert lasts ~1 year.)*

</details>

> **Which should I pick?** Re-jailbreak rarely → **Sideloadly**. Want
> hands-off renewal → **AltStore** if a computer stays nearby, or **SideStore**
> if not. Already TrollStore-capable (≤ iOS 16.6.1) → **TrollStore** (permanent).
> Have a profile + cert and like the terminal → **Provisioning profile / cert**.
> Dopamine is *semi-untethered* (re-run after each reboot), but the installed app
> only needs to survive, so a 7-day resign is usually fine.

<details>
<summary><strong>Under the hood: why CLI signing is "sign, then install"</strong></summary>

Sideloading is really **two steps** - *sign* the `.ipa` with an identity the device
trusts, then *install* it. The full, tested commands (including how to obtain the
identity and profile) are in the **Provisioning profile / signing cert (CLI)** box
above; this note just explains the moving parts.

- **Sign** - needs a signing **identity** (cert + private key) *and* a
  **provisioning profile** listing your device UDID. Two signers:
  [`zsign`](https://github.com/zhlynn/zsign) (feed it a `.p12`) or
  [`applesign`](https://github.com/nowsecure/node-applesign) (signs straight from the
  macOS keychain by identity hash - no `.p12`). Both clone the profile's entitlements
  onto the app so iOS accepts it.
- **Install** - fully scriptable, and the tool depends on the iOS major version:
  - **≤ iOS 16:** `ideviceinstaller install Dopamine-signed.ipa` (libimobiledevice).
  - **iOS 17.0-17.3.1:** developer services route through a root tunnel - run
    `sudo python3 -m pymobiledevice3 remote tunneld` in its own terminal, then
    `pymobiledevice3 apps install Dopamine-signed.ipa`.
  - A TrollStore `.tipa` is already permanently signed, so it installs as-is - but
    TrollStore only exists on ≤ 16.6.1, not iOS 17.

> **The one piece that isn't a clean one-liner:** *free Apple Account* (7-day) signing
> still relies on AltServer's Apple-Account-auth + anisette flow, so it's not a single
> command. With a real dev cert, the `zsign`/`applesign` → install path above is the
> clean headless route; otherwise let Sideloadly/AltStore do the one-time
> free-account signing and only the *install* is CLI.

</details>
