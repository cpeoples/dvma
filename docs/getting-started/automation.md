## Automation & test IDs

DVMA is a *target* app, so every interactive widget is instrumented with a
stable automation id. `testId(id, child)` in
[`lib/core/test_ids.dart`](https://github.com/cpeoples/dvma/blob/main/lib/core/test_ids.dart) attaches **both** a Flutter
`ValueKey` (for `appium-flutter-driver`) **and** a `Semantics(identifier:)`
node (surfacing as an Android `resource-id` / iOS `accessibilityIdentifier`
for native UiAutomator2 / XCUITest). Ids are derived from the registry
`vulnId` (`vuln_row_<id>`, `demo_screen_<id>`, `demo_action_<label>`,
`evidence_<label>`, plus `dvma_search_field` / `dvma_flavor_badge`).

The generator emits a machine-readable
[`automation/vuln_manifest.json`](https://github.com/cpeoples/dvma/blob/main/automation/vuln_manifest.json) listing every
module and its ids, so suites can walk every module without hardcoding.
Runnable example suites for **Appium** (WebdriverIO; both the Flutter driver
and native), **Espresso/UiAutomator** (Android), and **XCUITest** (iOS) live in
[`automation/`](https://github.com/cpeoples/dvma/blob/main/automation/), see [`automation/README.md`](https://github.com/cpeoples/dvma/blob/main/automation/README.md)
for setup and run commands. The flagship Appium spec opens every module,
triggers its demo action, and screenshots each into `artifacts/`.

## Testing

The Dart/Flutter test commands you'll run most often:

```sh
flutter analyze                    # static analysis (config/analysis_options.yaml)
flutter test                       # unit + widget tests
flutter test integration_test      # end-to-end regression suite (needs a device)
```

The `integration_test/` suite is a **regression suite**: each flow drives the
UI to the vulnerable path and asserts the *insecure* behavior is still present,
so an accidental "fix" that would break a training scenario fails CI.
`integration_test/app_test.dart` walks every module in one pass.

## Native Espresso walk on an emulator

The Android native walk (`DvmaWalkAllModulesTest` / `DvmaSmokeTest`, committed
under `android/app/src/androidTest/`) drives the built app through UiAutomator.
An emulator counts as a device, so no physical phone is needed. First make sure
`ANDROID_HOME` + `JAVA_HOME` are set (see
[Prerequisites → environment variables](/getting-started/prerequisites/#host-toolchain));
`flutter doctor` should show a green Android toolchain.

Create an AVD once (skip if you already have one, `emulator -list-avds`):

```sh
sdkmanager "emulator" "platform-tools" "system-images;android-34;google_apis;arm64-v8a"
avdmanager create avd -n dvma_api34 -d pixel_7 \
  -k "system-images;android-34;google_apis;arm64-v8a"   # x86_64 image on Intel hosts
```

Boot it and wait until it's fully ready:

```sh
emulator -avd dvma_api34 &                 # drop -no-window if you want to watch it
adb wait-for-device
until [ "$(adb shell getprop sys.boot_completed | tr -d '\r')" = 1 ]; do sleep 2; done
adb devices                                # confirm: emulator-5554   device
```

Build the debug APK, then run the native suite (the `dvmaAndroidTest` property
opts the instrumentation sources in, a normal build never compiles them):

```sh
flutter build apk --debug --dart-define-from-file=config/flavors/full.json
cd android && ./gradlew connectedDebugAndroidTest -PdvmaAndroidTest=true

# Just the fast smoke class:
./gradlew connectedDebugAndroidTest -PdvmaAndroidTest=true \
  -Pandroid.testInstrumentationRunnerArguments.class=com.dvma.DvmaSmokeTest
```

Prefer a one-shot? [`automation/scripts/appium_run_android.sh`](https://github.com/cpeoples/dvma/blob/main/automation/scripts/appium_run_android.sh)
runs the equivalent Appium walk and **auto-resolves `ANDROID_HOME`/`JAVA_HOME`
for you**, handy when you don't want to touch your shell profile. Full native
setup notes live in [`automation/README.md`](https://github.com/cpeoples/dvma/blob/main/automation/README.md).

The same script works on **both an emulator and a physical Android device** -
it just uses whatever `adb devices` shows, installs the APK, walks, and pulls
artifacts with `adb pull`. No mode flag needed.

## Appium walk on iOS (Simulator *or* physical device)

[`automation/scripts/appium_run_ios.sh`](https://github.com/cpeoples/dvma/blob/main/automation/scripts/appium_run_ios.sh)
is the iOS counterpart to the Android harness and drives the **same**
cross-platform walk spec ([`walk-all-modules.e2e.js`](https://github.com/cpeoples/dvma/blob/main/automation/appium/test/walk-all-modules.e2e.js))
via Appium's XCUITest driver. It targets **either** the Simulator or an attached
device and auto-detects which:

```sh
automation/scripts/appium_run_ios.sh              # auto: device if one is attached, else Simulator
DEVICE=0 automation/scripts/appium_run_ios.sh     # force Simulator
DEVICE=1 automation/scripts/appium_run_ios.sh     # force the attached device
DEVICE=1 USE_PREBUILT_WDA=1 automation/scripts/appium_run_ios.sh   # later device runs: reuse the signed WDA
```

**Prerequisites** (device mode): the Appium **`xcuitest` driver**
(`appium driver install xcuitest`), **`libimobiledevice` + `ideviceinstaller`**
(`brew install libimobiledevice ideviceinstaller`), the full **Xcode** app (not
just Command Line Tools), and - for the SSH artifact pull - a **jailbroken**
device with OpenSSH. Simulator mode needs only Xcode + the `xcuitest` driver.

- **Simulator** - builds `flutter build ios --debug --simulator`, boots the sim,
  and pulls artifacts from the Mac-side container with `simctl`. No device,
  signing, or jailbreak needed.
- **Physical device** - builds a **signed `--profile`** device app (a *profile*
  build, not debug: on a real device a debug build waits for a debugger and shows
  the Flutter "Debug" launch screen, so its UI/accessibility tree never renders
  and the walk finds nothing - profile renders the real UI). It signs with the
  team in
  [`ios/Flutter/Signing.xcconfig`](https://github.com/cpeoples/dvma/blob/main/ios/Flutter/Signing.xcconfig.example)
  (override with `XCODE_ORG_ID=`), installs with `ideviceinstaller`, and lets
  Appium sign + install its WebDriverAgent for your team. Because iOS has no
  `simctl`-style container access on device, the evidence pull uses **SSH/scp**
  from the app's `Documents/dvma-artifacts` container - the same mechanism as
  [Verify on iOS](/device-access/ios/verify/), so it needs a **jailbroken**
  device with OpenSSH. The harness finds the device IP automatically by matching
  its Wi-Fi MAC in the Mac's ARP table - so **turn off Private Wi-Fi Address on
  the device** (Settings → Wi-Fi → ⓘ → *Private Wi-Fi Address* off), or pass
  `DEVICE_IP=<ip>` (and `SSH_USER=` if not `mobile`). The `--flutter`-driver
  flavor still uses a debug build (it needs the Dart VM service).

> **First device run signs WebDriverAgent (WDA).** Appium installs its own
> helper app (WDA, bundle id `com.dvma.wda.xctrunner`) on the device to drive
> XCUITest. That needs a valid signing identity for your team - a free Apple
> account works, subject to the usual 7-day / device limits (see
> [CI & releases → the re-sign path](/getting-started/ci-and-releases/)). Set
> `USE_PREBUILT_WDA=1` on later runs to skip re-signing WDA every time.
>
> **You must be signed into Xcode with your Apple ID first.** WDA is a *new*
> bundle id, so Xcode has to auto-create a provisioning profile for it - and that
> only works when your Apple ID is registered in Xcode. If it isn't, the WDA
> build fails with `xcodebuild ... code 65` and, underneath:
>
> ```text
> error: No Accounts: Add a new account in Accounts settings.
> error: No profiles for 'com.dvma.wda.xctrunner' were found
> ```
>
> Fix it once: **Xcode → Settings (⌘,) → Accounts → `+` → Apple ID → sign in**
> with the Apple ID for your team, then re-run. (Re-run with
> `SHOW_XCODE_LOG=1` to see the raw xcodebuild signing output if it still fails.)
> This is the same account/identity the app itself uses; the app can sign without
> the account only because it reuses an already-cached `com.dvma` profile,
> whereas WDA's brand-new id has nothing cached until the account provisions it.

> **Permission prompts are handled for you.** Early in the walk iOS shows system
> permission dialogs (Local Network, Photos, Contacts, Tracking, Notifications,
> …) the first time a module touches a protected resource. The harness sets
> `autoAcceptAlerts: true`, so Appium **auto-accepts** them - you don't tap
> anything, and it's the intended behavior (many modules need the permission
> *granted* to reach the vulnerable path and emit evidence). You'll see them
> flash by; that's expected. If you ever want to reset granted permissions before
> a fresh run, revoke them under **Settings → Privacy & Security**, or reinstall
> the app.

## Native XCUITest walk on iOS (Simulator vs. physical device)

The iOS native walk is the `RunnerUITests` target
([`ios/RunnerUITests/`](https://github.com/cpeoples/dvma/blob/main/ios/RunnerUITests/):
`DVMASmokeUITests`, `DVMAWalkAllModulesUITests`).
[`automation/scripts/capture_run_ios.sh`](https://github.com/cpeoples/dvma/blob/main/automation/scripts/capture_run_ios.sh)
drives it on the **Simulator** and pulls every real artifact into `report-ios.md`
with just `simctl` - no device, backup, or jailbreak needed. This is the
recommended way to get full-fidelity iOS evidence:

```sh
automation/scripts/capture_run_ios.sh          # boots a sim, walks, pulls artifacts
```

> **Running the walk on a *physical* device is destination-sensitive.** The same
> target runs cleanly on the Simulator, but on a real device you may hit:
>
> ```text
> Cannot test target "RunnerUITests" on "<device>": Logic Testing Unavailable
> ```
>
> This is **not** a project-config bug - it means Xcode's **CoreDevice** layer
> can't fully pair with / resolve the device as a runnable test host, so the test
> scheduler downgrades the UI test to a "logic test" (which can't run on device).
> It's common with an **older device on a newer Xcode** (e.g. iPhone X / iOS 16.7
> under Xcode 26). Diagnose with:
>
> ```sh
> xcrun devicectl list devices          # device should be state: connected/available
> xcrun devicectl device info details --device <UDID>
> ```
>
> If it shows `state: unavailable` / `pairing: unsupported` / an empty build
> number, fix the **environment**, not the project: unlock + replug the phone and
> tap **Trust**; in **Xcode → Window → Devices and Simulators** let it finish
> *"Preparing device for development"*; ensure **Developer Mode** is ON
> (Settings → Privacy & Security). If CoreDevice still rejects it, use an Xcode
> version that fully supports that iOS, or fall back to the Simulator walk above
> plus a manual on-device spot-check (open the app, tap a module, then pull its
> artifact over SSH - see [Verify iOS artifacts](/device-access/ios/verify/)).
>
> The UI-test target itself is correctly configured (product-type `ui-testing`,
> `TEST_TARGET_NAME = Runner`, Sources+Frameworks+Resources build phases), so
> once CoreDevice reports the device as available the on-device run works with
> `xcodebuild test -only-testing:RunnerUITests -destination "platform=iOS,id=<UDID>"
> -allowProvisioningUpdates`.

## Linting & code quality

**The one local gate is `make check`** (format, `flutter analyze`, generator
drift, app-id sync, registry schema, standards-link resolution), with
`make test` adding the Dart unit/widget suite and `make check-all` adding the
full multi-language pre-commit run. `make` ships with macOS (Xcode CLT) and
Linux; on **Windows** either run the commands from **WSL / Git Bash**, or invoke
the underlying tools directly since they are all cross-platform:

```sh
dart run tool/generate.dart        # regenerate; then check nothing drifted
dart run tool/sync_app_id.dart --check
dart format --output=none --set-exit-if-changed lib tool test integration_test
flutter analyze
python3 automation/scripts/validate_registry.py
python3 automation/scripts/standards_mapping_audit.py --check
```

Or install the commit hook, which runs the same multi-language suite on every
commit on any OS: `pip install pre-commit && pre-commit install`. The
device/demo shell scripts under `automation/scripts/*.sh` are macOS/Linux (use
WSL on Windows); Dart/Flutter/Python tooling and `pre-commit` run natively
everywhere.

**All linting is Flutter/Dart, there is no Xcode- or Gradle-side linter.**
`flutter analyze` (the Dart analyzer + `flutter_lints`, configured in
[`config/analysis_options.yaml`](https://github.com/cpeoples/dvma/blob/main/config/analysis_options.yaml)) is the single
quality gate, and it's exactly what CI enforces
([`.github/workflows/ci.yml`](https://github.com/cpeoples/dvma/blob/main/.github/workflows/ci.yml) runs `generate` →
`flutter analyze` → `flutter test`).

```sh
flutter analyze                         # the lint gate (matches CI)
dart format --set-exit-if-changed lib   # optional: enforce Dart formatting
```

Notes:

- The analyzer **excludes `ios/**` and `android/**`**, the native folders are
  the standard Flutter host with almost no first-party code, so there's nothing
  to lint there. Xcode only surfaces ordinary build-time compiler warnings for
  the `Runner` target; it isn't a maintained lint suite you configure.
- No SwiftLint / detekt / clang-tidy is wired up **on purpose**: DVMA ships
  deliberately-weak code, and several lints that would flag it (`avoid_print`
  for the logging module, `deprecated_member_use` for weak-API demos) are
  relaxed in `analysis_options.yaml` so `flutter analyze` stays green without
  hiding the vulnerabilities.

Things automated in-app tests structurally can't cover (SSL pinning bypass
under an active MITM, Frida detection, static APK analysis) are captured per
module in the registry's `manual_test:` field and rendered as the platform-split
[Manual Testing](/manual-testing/) checklist.

## Adding a new vulnerability

The registry is the single source of truth:

1. Append an entry under the right category in
   `config/registry/categories/<category>.yaml` (unique `id`, title, difficulty,
   MASVS/MASTG/CWE refs, tools, summary; add `platforms: [android]` / `[ios]`
   or a `platform_note` if it isn't a shared cross-platform class). If the module
   needs an external/manual verification step the in-app tests can't drive (MITM,
   Frida, drozer, static analysis), add a `manual_test:` line - it's rendered into
   the platform-split [Manual Testing](/manual-testing/) checklist automatically.
   Omit it for modules fully proven by `integration_test/`. A large
   category may instead be a directory of numbered shards
   (`categories/<category>/NN_*.yaml`) that merge in sorted order, e.g.
   `platform/`, so append to the appropriate shard. For a shared
   module whose tooling differs per OS, keep the common tools in `tools:` and
   add `tools_android:` / `tools_ios:` for the OS-specific extras. Tool names
   are linked in the docs via the canonical `meta.tool_links` catalog in the
   registry - if you introduce a new tool, add its official homepage there so it
   renders as a clickable chip (names absent from the catalog, e.g. descriptive
   artifacts like `crafted prompt`, render as plain text).
2. Run `dart run tool/generate.dart`. This regenerates
   `lib/vulnerability_registry.dart` + `lib/core/module_router.dart`, and
   scaffolds a screen stub (`lib/modules/<category>/<id>/<id>_screen.dart`) and
   a doc stub (`docs/vulnerabilities/<id>.md`) if they don't exist.

   **Standards tags are required and enforced.** Every entry must carry at least
   one `masvs`, one `cwe`, one `maswe`, and an `owasp_mobile` category. `dart run
   tool/generate.dart` (which CI runs) **exits non-zero** and names any module
   missing one, so a contribution without full standards mapping fails the build.
   Every module in the registry satisfies this today, and the gate keeps future
   contributions honest.
3. Implement the vulnerable behavior in the screen, add an
   `integration_test/` flow and (if there's helper logic) a unit test.
