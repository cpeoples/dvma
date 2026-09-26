Before the install/build steps below, make sure your **host** and any **physical
test devices** are set up. For emulator/simulator-only work you can skip the
device sections.

## Host toolchain

| You want to build for… | You need |
| --- | --- |
| **Android** (any OS) | Android Studio **or** the Android command-line tools (SDK + platform-tools), **plus a JDK 17+** |
| **iOS** (macOS only) | The **full Xcode app** from the App Store, **not** just the standalone Command Line Tools |
| **Appium/WebdriverIO automation** (optional) | **Node.js 18+** (only if you use the Appium harnesses or `automation/appium/`) |

> **Android needs a JDK (17+):** Gradle won't build without one. Android Studio
> bundles a suitable runtime, but if you installed only the command-line tools,
> install a JDK and point `JAVA_HOME` at it. On macOS a bare `java` on `PATH` is
> just a stub, set `JAVA_HOME` to a real JDK.
>
> **<i class="fa-brands fa-apple"></i> macOS** (Homebrew):
>
> ```sh
> brew install openjdk@17 && export JAVA_HOME=/opt/homebrew/opt/openjdk@17
> ```
>
> **<i class="fa-brands fa-linux"></i> Debian/Ubuntu**:
>
> ```sh
> sudo apt-get install -y openjdk-17-jdk
> ```
>
> **<i class="fa-brands fa-windows"></i> Windows** (winget):
>
> ```sh
> winget install --id EclipseAdoptium.Temurin.17.JDK
> ```

<br/>

> **Point your shell at the SDK + JDK (`ANDROID_HOME` / `JAVA_HOME`).** If you
> installed the **command-line tools only** (no Android Studio), your shell
> needs three things so `adb`, `emulator`, `sdkmanager`, and Gradle can find the
> SDK and a real JDK: `ANDROID_HOME`, `JAVA_HOME`, and both on `PATH`. (Android
> Studio sets `ANDROID_HOME` for you; a Homebrew `openjdk` still needs
> `JAVA_HOME`.) Verify with `flutter doctor`, a green Android toolchain means
> these are set. **The Appium harnesses (`automation/scripts/appium_run_*.sh`,
> `verify_all_modules.sh`) auto-resolve all of this**, so you only need these
> exports for the *manual* `adb`/`emulator`/`./gradlew` commands.
>
> Add the block for your shell to its startup file so it persists across
> sessions (adjust the SDK path, Homebrew's is shown; Android Studio installs
> to `~/Library/Android/sdk` on macOS, `~/Android/Sdk` on Linux):
>
> **<i class="fa-brands fa-apple"></i> macOS** (zsh, the default; appends to `~/.zshrc`):
>
> ```sh
> cat >> ~/.zshrc <<'EOF'
> export ANDROID_HOME="/opt/homebrew/share/android-commandlinetools"
> export JAVA_HOME="/opt/homebrew/opt/openjdk@17"
> export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
> EOF
> source ~/.zshrc
> ```
>
> **<i class="fa-brands fa-linux"></i> Linux** (bash, appends to `~/.bashrc`; use `~/.profile` for login shells):
>
> ```sh
> cat >> ~/.bashrc <<'EOF'
> export ANDROID_HOME="$HOME/Android/Sdk"
> export JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"
> export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
> EOF
> source ~/.bashrc
> ```
>
> **<i class="fa-brands fa-windows"></i> Windows** (PowerShell, persists to your user environment):
>
> ```powershell
> setx ANDROID_HOME "$env:LOCALAPPDATA\Android\Sdk"
> setx JAVA_HOME "C:\Program Files\Eclipse Adoptium\jdk-17"
> # Then add these to your PATH (reopen the terminal afterwards):
> #   %ANDROID_HOME%\platform-tools  %ANDROID_HOME%\emulator  %ANDROID_HOME%\cmdline-tools\latest\bin  %JAVA_HOME%\bin
> ```

<br/>

> **Xcode vs. "Command Line Tools":** `xcode-select --install` installs only the
> standalone CLT (git, clang, etc.). That is **not enough** to build or deploy an
> iOS app, building for a device/simulator requires the full Xcode app plus its
> bundled SDKs. After installing Xcode, point the toolchain at it and accept the
> licenses (macOS steps are in [Installing Flutter](/getting-started/installing-flutter/)):
>
> ```sh
> sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
> sudo xcodebuild -runFirstLaunch
> ```
>
> iOS development is **macOS-only**, Xcode does not exist for Windows or Linux.

<br/>

> **Node.js (only for Appium automation):** the UI-automation harnesses
> (`automation/scripts/appium_run_*.sh`) and the `automation/appium/` suite run
> on Node. Skip this if you're only building/running the app by hand.
>
> **<i class="fa-brands fa-apple"></i> macOS** (Homebrew):
>
> ```sh
> brew install node
> ```
>
> **<i class="fa-brands fa-linux"></i> Debian/Ubuntu**:
>
> ```sh
> sudo apt-get install -y nodejs npm
> ```
>
> **<i class="fa-brands fa-windows"></i> Windows** (winget):
>
> ```sh
> winget install OpenJS.NodeJS.LTS
> ```

Run `flutter doctor` after setup; it flags anything missing for the platforms you
plan to target.

## Android device (physical)

1. Enable **Developer options**: Settings → About phone → tap **Build number** 7×.
2. Settings → System → Developer options → turn on **USB debugging**.
3. Connect over USB and **accept the "Allow USB debugging?" RSA prompt** on the
   phone (tick "Always allow from this computer"). Re-accept if you switch cables
   or ports.
4. Verify the host sees it: `adb devices` should list the serial as `device` (not
   `unauthorized` or `offline`). If it flaps, try a different cable/port and
   `adb kill-server && adb start-server`.

### Brand-new or factory-reset device (first boot)

A fresh phone - out of the box, or straight after a factory reset / full
re-flash - boots into the **Setup Wizard**, and the wizard **blocks the Settings
app entirely**. You cannot reach *About phone* to reveal Developer options until
setup is finished, and a factory reset also **wipes the previous USB-debugging
authorization**, so this must be redone even on a phone you'd used before.

1. **Finish or skip the Setup Wizard first.** Pick a language, then on the Wi-Fi
   step choose **Set up offline** / **Skip** (staying offline avoids the Google
   sign-in and is fastest). Skip PIN/biometrics and restore. This lands you on
   the home screen, where Settings becomes reachable.
2. **Reveal Developer options.**
   1. Open **Settings** and scroll down to **About phone**.
   2. Scroll to the bottom to find **Build number**.
   3. Tap **Build number** 7× rapidly (an on-screen countdown appears).
   4. Enter your PIN / password / pattern if prompted.
   5. You'll see **"You are now a developer!"**
   6. Go back to **Settings → System**; **Developer options** is just above
      **Reset options**.
   - Samsung (One UI): About phone → **Software information** → **Build number** 7×.
   - Xiaomi (MIUI): About phone → **MIUI version** 7×.
3. **Turn on the toggles.** Settings → System → **Developer options** → **USB
   debugging**.
4. Then follow steps 3-4 above to authorize the host.

> **Rooting/unlocking? Enable OEM unlocking first.** In **Developer options**,
> turn on **OEM unlocking** *before* you try `fastboot flashing unlock` - the
> bootloader unlock is refused without it. The toggle is often **greyed out
> until the device is connected to the internet** (it checks the unlock is
> permitted), so join Wi-Fi once if it won't enable. This is separate from USB
> debugging, and unlocking the bootloader later **wipes the device**.

## iOS device (physical)

1. **Developer Mode** (iOS 16+): Settings → Privacy & Security → **Developer
   Mode** → enable, then reboot. A signed build installs but **won't launch**
   without this.
2. Connect over USB and tap **Trust This Computer** on the iPhone.
3. Signing: open `ios/Runner.xcworkspace` in Xcode → **Signing & Capabilities** →
   pick your **Team** (a free Apple ID works). Unsigned builds won't install on a
   device; the Simulator needs no signing.
4. Free Apple ID provisioning expires after **7 days**, re-deploy weekly for
   ongoing testing. (A paid Apple Developer account lasts a year.)

> **Install fails with `0xe8008018` ("identity … no longer valid")?** The cert
> looks valid locally but Apple has **revoked** it server-side (common with free
> "Personal Team" certs). No CLI tool can re-mint it - you must let **Xcode's
> automatic signing** regenerate the cert via **Fix Issue**. Full step-by-step is
> in the **"⚠️ Install fails with `0xe8008018`"** box on the
> [iOS install page](/getting-started/ios/).

> **Finding your Team ID.** "Team" in Xcode maps to a 10-character Apple **Team
> ID**. Don't hardcode someone else's, use your own. Add your Apple ID under
> Xcode → **Settings → Accounts** first, then either pick the Team in Signing &
> Capabilities or set it via the xcconfig below. To look yours up from the CLI:
>
> ```sh
> # From an installed provisioning profile (most reliable, shows TeamName too):
> for p in ~/Library/Developer/Xcode/UserData/Provisioning\ Profiles/*.mobileprovision; do
>   security cms -D -i "$p" | plutil -extract TeamIdentifier xml1 -o - - | grep string
> done
>
> # Or list your code-signing identities (the name in quotes is your account):
> security find-identity -v -p codesigning
> ```
>
> If neither returns anything, you haven't signed a build yet, add your account
> in Xcode and let it create a profile once, then re-run.

<br/>

> **Set your Team via the local xcconfig (keeps IDs out of git).** The Xcode
> project references `DEVELOPMENT_TEAM = $(DEVELOPMENT_TEAM)`, resolved from a
> gitignored `ios/Flutter/Signing.xcconfig`. One-time setup:
>
> ```sh
> cp ios/Flutter/Signing.xcconfig.example ios/Flutter/Signing.xcconfig
> # then edit Signing.xcconfig and set DEVELOPMENT_TEAM to your own Team ID
> ```
>
> `Signing.xcconfig` is gitignored, so each contributor uses their own team and
> nobody's ID is committed. (Simulator builds need no signing, so this is only
> required for on-device builds.)

<br/>

> **Seeing the stock "Flutter Demo Home Page" counter instead of DVMA?** That
> means Xcode built a Flutter config pointing at the wrong project (a stale
> `ios/Flutter/Generated.xcconfig`, e.g. copied from a `flutter create`
> scaffold, sends the build to a different `lib/main.dart`). Regenerate the iOS
> build config for *this* repo, then clean-build:
>
> ```sh
> flutter clean
> flutter pub get
> flutter build ios --config-only    # rewrites Generated.xcconfig for this path
> ```
>
> Then in Xcode: **Product → Clean Build Folder** (⇧⌘K) and Run. Always open the
> **`.xcworkspace`**, never the `.xcodeproj`.
