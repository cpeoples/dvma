# DVMA Automation Suites

Runnable **dynamic-analysis UI-automation** examples for **DVMA** (Damn Vulnerable
Mobile App). DVMA is an *intentionally vulnerable* Flutter target app (in the
spirit of DVIA / DIVA). These suites drive the app end-to-end so a pentester's
dynamic-analysis tooling - an intercepting proxy, Frida, `logcat`/Console,
filesystem/Keychain watchers, etc. - observes **every** vulnerable code path.

> ⚠️ Authorized security-training use only. DVMA is deliberately insecure; run it
> only on disposable emulators/simulators or dedicated test devices.

The flagship "walk all modules" tests open **every** module in one run (the exact
count comes from `vuln_manifest.json` - currently 202), tap the first action on
each demo screen (triggering the vulnerable behavior), and save a screenshot per
module.

---

## Platform parity - what's 1:1 and what isn't

DVMA builds one Flutter codebase to both OSes, but **the catalog is not
symmetric**, so the automation deliberately does not fake 1:1 parity where the OS
has no equivalent. Each registry entry carries a `platforms:` list; `AppConfig`
hard-filters the catalog per running OS. Current split (from
`vuln_manifest.json`):

| Bucket | Count | Runs on | Automation |
| --- | ---: | --- | --- |
| **Shared** (no `platforms:`) | 135 | Android **and** iOS | Full parity: Appium (both - see note), Espresso walk-all (Android), XCUITest walk-all (iOS) |
| **Android-only** (`[android]`) | 51 | Android only | Android suites only - **no iOS equivalent exists** |
| **iOS-only** (`[ios]`) | 16 | iOS only | iOS suites only - **no Android equivalent exists** |

> **Appium, both platforms.** The Appium suite is cross-platform *by design*: the
> same specs run under `wdio.android.conf.js` / `wdio.ios.conf.js` (`test:ios*`
> scripts + the XCUITest driver). Both paths are exercised - the iOS run has a
> one-shot harness, [`automation/scripts/appium_run_ios.sh`](../automation/scripts/appium_run_ios.sh),
> that boots a Simulator, builds the `full` `.app`, starts Appium, runs the
> native walk, and collects the real evidence artifacts. The native XCUITest
> suite (`RunnerUITests`) covers the same iOS walk via `xcodebuild`.

**Why the asymmetric ones can't be ported (not a coverage gap - an OS reality):**

- **Android-only (51)** - mostly `platform` + `system_provider` IPC surfaces
  Android has and iOS does not: exported Activities/Services, implicit/ordered
  **broadcasts**, `ContentProvider`s + URI grants, `PendingIntent`, IME/keyboard
  services, `MediaProjection`, `AccessibilityService`, App Widgets, Binder. There
  is no iOS API to point an equivalent test at, so writing an iOS test would be
  dishonest.
- **iOS-only (16)** - Apple-specific surfaces Android lacks: **Keychain**
  access-group / state-integrity, **App Intents / Shortcuts**, **App Groups**,
  Handoff `NSUserActivity`, Universal Links / AASA, App Clips, WKWebView
  local-file reads, App Tracking Transparency.

**Parity policy for the walk-all suites.** The Espresso and XCUITest walk-all
drivers **discover rows dynamically** from the live home list, so each one
naturally walks *exactly* the modules its OS surfaces (shared + that OS's
platform set) - the Android run walks 135 + 51 = 186, the iOS run walks
135 + 16 = 151, with **no per-platform module list to maintain**. That is the
honest form of parity: identical test logic, OS-appropriate module set.

**The capture harness and `demo_*.sh` are Android-only by construction.**
`capture_run.sh`, `verify_all_modules.sh`, and the `demo_*.sh` scripts drive
`adb` / UiAutomator and the companion **Android** attacker app (`com.dvma.attacker`)
to prove *cross-app* Android trust-boundary crossings (broadcasts, exported
components, Binder). Those crossings do not exist on iOS, so there is
intentionally no iOS counterpart; the equivalent iOS artifact verification is
manual (device backup / jailbreak SSH - see the top-level README's
["Verifying iOS artifacts"](../README.md) note).

---

## Instrumentation model (read this first)

Every widget an automation script needs to find is wrapped by `testId(id, child)`
in [`lib/core/test_ids.dart`](../lib/core/test_ids.dart). That helper attaches
**both**:

| Layer | Mechanism | Found by |
| --- | --- | --- |
| Flutter | `ValueKey<String>(id)` | `appium-flutter-driver` → `find.byValueKey('<id>')` |
| Native (Android) | `Semantics(identifier: id)` → **`resource-id`** | UiAutomator2 (Appium `~id`/resource-id), UiAutomator (`By.res(id)`) |
| Native (iOS) | `Semantics(identifier: id)` → **`accessibilityIdentifier`** | XCUITest (`matching(identifier:)`), Appium `~id` |

Stable ids (see [`automation/vuln_manifest.json`](./vuln_manifest.json)):

- Home search field - `dvma_search_field`
- Flavor badge - `dvma_flavor_badge`
- Disclaimer banner - `dvma_disclaimer_banner`
- Category header - `category_<categoryId>`
- Vulnerability row (tap to open) - `vuln_row_<vulnId>`
- Demo screen root - `demo_screen_<vulnId>`
- Demo action button - `demo_action_<slug(label)>`
- Evidence panel - `evidence_<slug(label)>`

**The manifest is the source of truth.** `automation/vuln_manifest.json` is
generated by [`tool/generate.dart`](../tool/generate.dart) and lists every module
(`id`, `category`, `title`, `difficulty`, `rowId`, `screenId`) plus the top-level
`ids`, `categories`, and `count`. The Appium suite **loads this manifest at
runtime** and iterates it; the native suites discover rows by the `vuln_row_`
prefix (or can read an explicit list copied from the manifest).

### Keeping in sync

The ids and the manifest are generated. After adding/removing a module or
changing ids, **re-run the generator** so the manifest matches the app:

```bash
dart run tool/generate.dart
```

Then re-run the suites; coverage tracks the manifest automatically.

---

## App identifiers

Detected from the repo:

- **Android `applicationId`**: `com.dvma`
  (`android/app/build.gradle.kts`)
- **iOS bundle id**: `com.dvma`
  (`ios/Runner.xcodeproj`, `PRODUCT_BUNDLE_IDENTIFIER`)

> If you rename the app, update `APP_PACKAGE`/`BUNDLE_ID` (Appium env vars) and the
> `package`/`pkg` values in the native test sources.

---

## Building DVMA for testing

Build the **full** flavor so all modules are enabled:

```bash
# Android (debug APK - required for the appium-flutter-driver)
flutter build apk --debug --dart-define-from-file=config/flavors/full.json
# -> build/app/outputs/flutter-apk/app-debug.apk

# iOS (debug, simulator)
flutter build ios --debug --simulator \
  --dart-define-from-file=config/flavors/full.json
# -> build/ios/iphonesimulator/Runner.app
```

> **Android build prerequisite - a JDK (17+).** The Gradle build needs a real
> Java runtime. On macOS `/usr/bin/java` is only a stub, so a bare `java` on
> `PATH` isn't enough - set `JAVA_HOME` to a real JDK. The Android Studio
> bundled runtime (`…/Android Studio.app/Contents/jbr/Contents/Home`) works too.
>
> ```bash
> # macOS (Homebrew)
> brew install openjdk@17
> export JAVA_HOME=/opt/homebrew/opt/openjdk@17      # Apple silicon
> # export JAVA_HOME=/usr/local/opt/openjdk@17       # Intel
>
> # Debian/Ubuntu
> sudo apt-get install -y openjdk-17-jdk
> export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
>
> # Windows (winget) - then set JAVA_HOME to the install dir
> winget install --id EclipseAdoptium.Temurin.17.JDK
> ```
>
> The `appium_run_android.sh` harness auto-discovers a JDK (Homebrew `openjdk@17`
> → Homebrew `openjdk` → Android Studio JBR → `/usr/libexec/java_home`) and sets
> `JAVA_HOME` for you; set it yourself only if the build can't find one.

> **Driver caveat:** `appium-flutter-driver` needs the Dart VM service extension,
> which is present in **debug/profile** builds but stripped from release. The
> native flavors (UiAutomator2 / XCUITest / UiAutomator / XCUITest source suites)
> work against any build, including release.

---

## 1) Appium + WebdriverIO - the primary suite

Location: [`automation/appium/`](./appium). Supports **both** driver approaches
from the same specs, selected with the `DVMA_DRIVER` env var:

- `DVMA_DRIVER=flutter` (default) → `appium-flutter-driver` (find by `ValueKey`)
- `DVMA_DRIVER=native` → UiAutomator2 / XCUITest (find by accessibility id)

The helper [`lib/dvma.js`](./appium/lib/dvma.js) branches on the live session's
`automationName`, so `openModuleBySearch`, `findById`, `back`, `expandAllCategories`,
`tapAllDemoActions`, and `scrollToId` work in both modes.

### Install

**Prerequisite: Node.js ≥ 18** (Appium, WebdriverIO, and the harnesses all run
on Node). Check with `node --version`; if it's missing:

```bash
# macOS (Homebrew)
brew install node
# Debian/Ubuntu
sudo apt-get install -y nodejs npm
# Windows (winget) - or grab the installer from https://nodejs.org
winget install OpenJS.NodeJS.LTS
# Any OS: nvm (https://github.com/nvm-sh/nvm) - nvm install --lts
```

```bash
cd automation/appium
npm install                 # WebdriverIO + reporters (from package.json)

# Appium 2 + drivers are installed separately (not project deps):
npm i -g appium
appium driver install uiautomator2
appium driver install xcuitest
appium driver install --source=npm appium-flutter-driver

# Start the Appium server in another terminal:
appium
```

### Run

```bash
# Android - build the debug APK first (see "Building DVMA")
npm run test:android            # walk + smoke, Flutter driver (default)
npm run test:android:smoke      # smoke only
npm run test:android:walk       # walk all modules only

# Switch to the native UiAutomator2 driver:
DVMA_DRIVER=native npm run test:android:walk

# iOS (simulator)
npm run test:ios
DVMA_DRIVER=native npm run test:ios:walk
```

**Android one-shot harness.** [`automation/scripts/appium_run_android.sh`](../automation/scripts/appium_run_android.sh)
is the Android analogue - it auto-resolves `adb`, a JDK, `ANDROID_HOME`, and the
connected device, builds the `full` debug APK, primes the app container, starts
an Appium server, runs the native (UiAutomator2) walk, then pulls the evidence
files (app external files dir) + `DVMA-EVIDENCE` logcat lines + per-module
screenshots into `automation/artifacts/android-appium/`:

```bash
automation/scripts/appium_run_android.sh
# overrides: SERIAL=… SPEC=smoke SKIP_BUILD=1 DVMA_DRIVER=flutter
#            ADB=/path/to/adb JAVA_HOME=/path/to/jdk
```

Prerequisites: a JDK for the build (see "Building DVMA for testing" above), the
Android platform-tools (`adb`), and Node ≥ 18. Pass `SERIAL=<serial>` when more
than one device is attached (`adb devices`).

**iOS one-shot harness.** [`automation/scripts/appium_run_ios.sh`](../automation/scripts/appium_run_ios.sh)
does the whole flow end-to-end - resolve/boot a Simulator, disable the hardware
keyboard, build the `full` `.app`, start an Appium server, run the native walk,
then pull the real evidence files (app Documents container) + `os_log` lines +
per-module screenshots into `automation/artifacts/ios-appium/`:

```bash
automation/scripts/appium_run_ios.sh
# overrides: DEVICE_NAME=… UDID=… SPEC=smoke SKIP_BUILD=1 DVMA_DRIVER=flutter
```

The walk mirrors the native XCUITest/Espresso walks: it expands all category
sections, reads the app's own runtime module list (`dvma_module_manifest`,
falling back to `vuln_manifest.json`), navigates each module **by search**,
flips switches / nudges sliders, taps **all** `demo_action_*` buttons, and
asserts an `evidence_*` panel appeared.

### Useful env vars

| Var | Default | Purpose |
| --- | --- | --- |
| `DVMA_DRIVER` | `flutter` | `flutter` or `native` |
| `DVMA_MODULE_IDS` | (unset) | walk only these comma-separated module ids (targeted runs) |
| `APP_PATH` | debug artifact path | `.apk` / `.app` / `.ipa` to install |
| `APP_PACKAGE` | `com.dvma` | Android applicationId |
| `APP_ACTIVITY` | `.MainActivity` | Android launch activity |
| `BUNDLE_ID` | `com.dvma` | iOS bundle id |
| `DEVICE_NAME` | `Android Emulator` / `iPhone 17` | target device (ignored on iOS when `UDID` is set) |
| `PLATFORM_VERSION` | (unset) | OS version (iOS: only used when no `UDID`) |
| `UDID` | (unset) | specific device/simulator |
| `APPIUM_HOST` / `APPIUM_PORT` | `127.0.0.1` / `4723` | Appium server |
| `DVMA_DOCS_URL` | `https://cpeoples.github.io/dvma` | docs base the harnesses cite in error output; override for a fork/custom domain |

Screenshots are written to `automation/appium/artifacts/<id>.png`. `node_modules/`
and `artifacts/` are gitignored.

> **Flutter-driver note:** demo action buttons, evidence panels, and controls
> are matched by id *prefix* (`demo_action_*`, `evidence_*`). The Flutter finder
> matches a specific key, not a prefix, so in `flutter` mode the walk **skips**
> the action taps, control exercising, and evidence assertion (it still opens
> every screen and screenshots it). Use `DVMA_DRIVER=native` for the
> full-fidelity walk that taps every action and verifies evidence.

---

## 2) Espresso / UiAutomator - Android native example

Location: [`automation/espresso/`](./espresso) (the reference copies) - already
wired into `android/app/` and gated behind the `dvmaAndroidTest` Gradle property
(see "Wired in (opt-in)" below).

### The canvas / Semantics caveat

Flutter renders to a single native canvas, so **Espresso view matchers**
(`onView(withId(...))`) can't see individual widgets. These tests use
**UiAutomator** (`UiDevice`, `By.res(...)`, `By.desc(...)`), which reads the
accessibility tree where the `Semantics(identifier:)` values appear as
**resource-ids**. Espresso's runner/rules still bootstrap the instrumentation.

### Wired in (opt-in)

The two Kotlin sources are already committed to the Android host at
`android/app/src/androidTest/kotlin/com/dvma/`, and
`android/app/build.gradle.kts` adds the instrumentation runner, deps, and source
set **only when you opt in** with the `dvmaAndroidTest` Gradle property. Normal
`flutter build` / `flutter run` never compile or ship these sources.

> The `androidTest` dependency versions are pinned to match the `androidx.test`
> versions Flutter already resolves on the runtime classpath - AGP's consistent
> resolution rejects mismatched versions.

### Run

```bash
flutter build apk --debug --dart-define-from-file=config/flavors/full.json
cd android && ./gradlew connectedDebugAndroidTest -PdvmaAndroidTest=true

# Run a single class (e.g. the fast smoke test):
./gradlew connectedDebugAndroidTest -PdvmaAndroidTest=true \
  -Pandroid.testInstrumentationRunnerArguments.class=com.dvma.DvmaSmokeTest
```

Without `-PdvmaAndroidTest=true` the suite is inert (sources excluded, no test
deps), so it never affects a normal app build.

`DvmaWalkAllModulesTest` discovers `vuln_row_*` rows dynamically (or set
`USE_MANIFEST_LIST = true` and paste ids from the manifest). Screenshots are saved
on-device to the app's external files dir; pull them with:

```bash
adb shell 'run-as com.dvma ls files' 2>/dev/null || true
adb pull "$(adb shell echo /sdcard/Android/data/com.dvma/files/dvma-artifacts)" ./artifacts-android
```

(The exact path depends on `getExternalFilesDir`; check the test log output.)

---

## 3) XCUITest - iOS native example

Location: [`automation/xcuitest/`](./xcuitest) (reference copies). Unlike a stock
Flutter project, the UI-testing target is **already wired into the Xcode
project**, mirroring how the Android `androidTest/` sources are committed to the
host. The two Swift sources also live at `ios/RunnerUITests/` and build as the
`RunnerUITests` target (`com.apple.product-type.bundle.ui-testing`), so
`xcodebuild test` works with no manual Xcode setup.

### accessibilityIdentifier mapping

Flutter's `Semantics(identifier:)` surfaces on iOS as each element's
**`accessibilityIdentifier`**. XCUITest locates elements by identifier
(`matching(identifier:)` / subscripting). Because the UI is one canvas, elements
often appear as `otherElements`; the `DVMAQuery.element` helper searches across
all element types by identifier for robustness.

### Wired in (target: `RunnerUITests`)

- `ios/RunnerUITests/DVMASmokeUITests.swift` and
  `ios/RunnerUITests/DVMAWalkAllModulesUITests.swift` are members of the
  `RunnerUITests` UI-testing target; its *Target to be Tested* is `Runner`.
- The `Runner` shared scheme lists `RunnerUITests` as a testable, so
  `-scheme Runner` builds and runs it.
- **No app/bundle-id is hardcoded** in the tests: `XCUIApplication()` launches
  the wired *target-to-be-tested* (`Runner`). To drive a differently-named build
  without editing the project, set `DVMA_BUNDLE_ID` in the run environment
  (see `DVMAApp.make()`), e.g. `DVMA_BUNDLE_ID=com.dvma.dev`.
- The target's own bundle id is `$(PRODUCT_BUNDLE_IDENTIFIER)` =
  `com.dvma.RunnerUITests`, and `DEVELOPMENT_TEAM = $(DEVELOPMENT_TEAM)` - so it
  picks up the same gitignored `ios/Flutter/Signing.xcconfig` team id as the app
  (device runs only; the Simulator needs no signing).

The reference copies under `automation/xcuitest/` track the wired-in sources and
differ only in their self-describing header comment; edit either and copy the
logic across to keep them in sync.

### Run

```bash
# Generate the Flutter config so the app builds (once / after pubspec changes):
flutter build ios --config-only \
  --dart-define-from-file=config/flavors/full.json

# Compile the UI-test target (fast sanity check, no signing on the Simulator):
xcodebuild build-for-testing \
  -project ios/Runner.xcodeproj \
  -scheme Runner \
  -destination 'platform=iOS Simulator,name=iPhone 17' \
  -only-testing:RunnerUITests \
  CODE_SIGNING_ALLOWED=NO

# Run the UI tests on a Simulator:
xcodebuild test \
  -project ios/Runner.xcodeproj \
  -scheme Runner \
  -destination 'platform=iOS Simulator,name=iPhone 17' \
  -only-testing:RunnerUITests

# Run just the smoke test (fast):
xcodebuild test ... -only-testing:RunnerUITests/DVMASmokeUITests

# On a physical device, add your team (see "iOS device" in the top-level README)
# and target it by name/UDID instead:
#   -destination 'platform=iOS,name=<your iPhone>'
```

> Use `-project ios/Runner.xcodeproj` (the `RunnerUITests` scheme testable lives
> there). `-workspace ios/Runner.xcworkspace` also works if you prefer the
> workspace. Pick any installed Simulator from `xcrun simctl list devices`.

`DVMAWalkAllModulesUITests` discovers `vuln_row_*` identifiers dynamically (or set
`useExplicitList = true` and paste ids from the manifest). Per-module screenshots
are attached to the test report as `XCTAttachment`s (view in the Xcode Report
navigator or the `.xcresult` bundle).

---

## 4) Capture harness - record what every module actually does

Location: [`automation/scripts/`](./scripts). Where the suites above *drive* the
UI, the capture harness *records the real artifacts* each vulnerable path
produces - logcat evidence lines, on-device files, `shared_prefs`, SQLite DBs,
and (optionally) network flows - and assembles them into a single Markdown
report at `automation/artifacts/report.md`.

```bash
# 1) (optional) capture network flows in another terminal:
python3 automation/scripts/capture_listener.py --https 8443 --daemon
adb reverse tcp:8443 tcp:8443    # route device localhost -> host listener

# 2) build a debug APK with androidTest wired in, then run the harness:
automation/scripts/capture_run.sh
# -> automation/artifacts/report.md
```

| Script | Role |
| --- | --- |
| `capture_listener.py` | local HTTP/HTTPS server that logs every request (method/path/headers/body) to `capture_flows.jsonl` |
| `capture_run.sh` | clears logcat, runs the walk-all instrumentation, pulls on-device artifacts, assembles the report |
| `build_capture_report.py` | correlates logcat + files + prefs + DBs + flows into `report.md` |
| `demo.sh <otp\|broadcast\|components>` | single entry point for the three companion-attacker demos below (forwards `SERIAL`/`SKIP_BUILD`/`FLAVOR`/`ADB`) |
| `demo_cross_app_otp.sh` | one-command narrated demo of the cross-app OTP leak (installs both apps, drives DVMA by Semantics id, shows the attacker harvest + the secure-path block) |
| `demo_broadcast_ipc.sh` | end-to-end demo/verification for the broadcast-IPC modules (receive-side spoof/forge + send-side implicit/ordered/role-delegate), asserting the cross-app effect in logcat |
| `demo_exported_components.sh` | end-to-end demo/verification for the exported-component modules (8 exported Activities + 1 exported Service bind + task-stack hijack); force-stops **both** apps before each `--es start`/`--es bind` (killing only the attacker leaves DVMA's NoDisplay/WebView activities reparented in the attacker's task, polluting the next fresh onCreate so BAL drops the launch), then asserts DVMA's `DVMA-EVIDENCE` effect - plus the attacker's harvest for the service bind, and a `dumpsys` task-placement check for the StrandHogg reparent |

### Cross-app demos - the companion attacker app

Some modules model an attack whose premise is a *second co-resident app*
crossing an Android trust boundary. These cannot be shown truthfully inside
DVMA alone (one app can't attack itself across an IPC boundary). The
standalone [`companion/dvma-attacker/`](../companion/dvma-attacker)
project (`com.dvma.attacker`, a separate package/UID/signing key requesting no
dangerous permissions) is that "malicious co-resident app". It is a
deterministic IPC peer - **not** an agent.

**Proven vertical - `cross_app_otp_credential_leak`.** DVMA fires a *real*
unprotected broadcast (`…action.OTP_ISSUED`, no receiver permission) from its
native `MethodChannel`; the attacker's foreground-service receiver harvests the
OTP + auth deep link. The permission-scoped button gates delivery behind a
signature-level permission, so the differently-signed attacker gets nothing.

Three ways to run it (from the repo root):

```bash
# 1) One-command narrated demo (no manual taps; drives DVMA by Semantics id)
automation/scripts/demo.sh otp
SKIP_BUILD=1 automation/scripts/demo.sh otp   # reuse built APKs

# 2) CI-grade pass/fail regression (skips cleanly if the attacker isn't installed)
cd android && ./gradlew connectedDebugAndroidTest -PdvmaAndroidTest=true \
  -Pandroid.testInstrumentationRunnerArguments.class=com.dvma.DvmaCrossAppOtpLeakTest

# 3) Fold the cross-app capture into the full multi-module report
ATTACKER=1 automation/scripts/capture_run.sh
```

**Broadcast-IPC group.** `automation/scripts/demo.sh broadcast` covers the
receive-side (attacker sends → DVMA's exported receiver applies) and send-side
(DVMA emits → attacker receives/reorders) broadcast modules, asserting the
cross-app effect in `DVMA-EVIDENCE`/`DVMA-ATTACKER` logcat.

**Exported-component group.** `automation/scripts/demo.sh components`
covers the 8 exported-Activity modules, the exported-Service bind, and the
task-stack hijack. The attacker reaches each by explicit component name from its
own UID (`am start … --es start/bind <kind>`). Each case force-stops **both**
apps and cold-starts the attacker so the extra lands in a fresh `onCreate`
(otherwise Android's background-activity-launch limits drop the start, and a
stale DVMA activity left in the attacker's task poisons the next start). It
asserts `DVMA-EVIDENCE` per module, plus the attacker's harvest for the service
bind, and a `dumpsys` task-placement check for the hijack. `adb` is auto-located
(PATH → `$ANDROID_HOME`/`$ANDROID_SDK_ROOT` → default SDK path; override with
`ADB=`); pass `SERIAL=<serial>` when more than one device is attached. See the
companion [README](../companion/dvma-attacker/README.md) for the full trigger
map.

```bash
automation/scripts/demo.sh components
SKIP_BUILD=1 automation/scripts/demo.sh components   # reuse built APKs
```

> **The only manual prerequisite** for the manual path is launching the attacker
> app once (that starts its harvest foreground service); it then keeps
> harvesting while DVMA is foreground. The demo script and `ATTACKER=1` harness
> do this for you. See the companion
> [README](../companion/dvma-attacker/README.md) for the flow diagram, the
> Android-8+ implicit-broadcast rationale, and the OEM battery caveat.

---

## 5) iOS capture harness - verify findings on the Simulator

Location: [`automation/scripts/capture_run_ios.sh`](./scripts/capture_run_ios.sh).
The iOS analogue of `capture_run.sh`. It boots a Simulator, runs the native
`RunnerUITests` walk, then pulls the **real** artifacts each module wrote and
assembles `automation/artifacts/ios/report-ios.md`.

```bash
automation/scripts/capture_run_ios.sh
# reuse an already-walked app (skip the XCUITest run, just re-pull + re-report):
SKIP_TEST=1 automation/scripts/capture_run_ios.sh
# pick a specific simulator:
UDID=<sim-udid> automation/scripts/capture_run_ios.sh     # xcrun simctl list devices
```

### Why the Simulator makes this easy (no jailbreak needed)

The evidence sink writes, on iOS, to the app's **Documents** dir
(`Documents/dvma-artifacts/<vulnId>.txt`) and mirrors every record to **os_log**
under the `DVMA-EVIDENCE` name. On the Simulator the app container is a real
folder on your Mac, so the harness reads it directly with `simctl` - no device
backup, no jailbreak, no adb-equivalent:

```bash
UDID=<booted-sim>
xcrun simctl get_app_container "$UDID" com.dvma data      # -> the app container path
cat "$(xcrun simctl get_app_container "$UDID" com.dvma data)/Documents/dvma-artifacts/"*.txt
xcrun simctl spawn "$UDID" log stream --style syslog \
  --predicate 'eventMessage CONTAINS "DVMA-EVIDENCE"'      # the os_log analogue of logcat
```

### iOS evidence tiers - real vs simulated

Not every finding is a native iOS OS probe; the harness report records which is
which:

| Tier | Modules | On iOS | Verified by |
| --- | --- | --- | --- |
| **A** | most storage / crypto / auth / network / input (plus the Keychain modules, which write a real `NSUserDefaults` plist) | **Real** I/O - a real `UserDefaults` plist, SQLite DB, temp file, socket, ciphertext (identical Dart code to Android) | The pulled artifact file + os_log - a genuine on-disk/on-wire artifact |
| **B-real** | `resilience` (root/jailbreak, debugger, emulator, Frida, tamper) plus `app_group_shared_container_amplification` | **Real** - resilience via `ios/Runner/DvmaNativeProbes.swift` (jailbreak markers + sandbox write, `sysctl P_TRACED`, simulator env, dyld Frida-image scan + port 27042, embedded-profile digest); App Group via `dvma/app_group` (`containerURL(forSecurityApplicationGroupIdentifier:)` cross-member write/read), entitlement-gated: genuine on an App-Group-signed build, `entitlement-missing` + in-Dart fallback otherwise | os_log `DVMA-EVIDENCE` line from the native probe |
| **B-nosim** | `system_provider`, the IPC groups, cross-app OTP | **Simulated** - these model Android-only trust boundaries (implicit broadcasts, exported components, ContentProviders, Binder) with no iOS equivalent, so the Dart bridge stays `Platform.isAndroid`-gated and the module runs its in-Dart model | Simulation; a native iOS probe is intentionally not built |
| **C** | iOS-only App Intents / Shortcuts / Universal Links / WKWebView, etc. | **Simulated** - no discrete iOS OS probe wired (many are UI/URL-routing surfaces with no self-contained probe) | Simulation |

For **Tier A** (the majority), iOS verification is as real as Android - the same
code wrote the same artifact; you just collect it via `simctl` instead of `adb`.

### The Swift native-probe seam (`DvmaNativeProbes.swift`)

[`ios/Runner/DvmaNativeProbes.swift`](../ios/Runner/DvmaNativeProbes.swift)
registers the same `MethodChannel` names as the Android `*Probe.kt` / `*Ipc.kt`
handlers (`dvma/resilience`, `dvma/system_provider`, …).

The **`dvma/resilience`** channel is **implemented for real**: jailbreak markers +
a sandbox-write escape, `sysctl(KERN_PROC)`/`P_TRACED` for a debugger, the
Simulator environment, a dyld Frida-image scan + port-27042 probe, and an
embedded-profile digest. Its Dart bridge `isAvailable` is now `Android || iOS`,
so the 5 resilience modules produce a **real native iOS signal** (the modules are
still vulnerable because they gate the decision on a bypassable client-side
boolean - that's the intended bug).

The **`dvma/app_group`** channel is also **implemented** (`sharedContainerLeak`):
on an App-Group-entitled iOS build it obtains the shared container via
`containerURL(forSecurityApplicationGroupIdentifier:)` and does a genuine
cross-member file write→read (a real artifact); on an unentitled/unsigned build
it returns `detected=false reason=entitlement-missing …` and the Dart module
falls back to its deterministic simulation - honest either way. Arming the real
path needs [`ios/Runner/Runner.entitlements`](../ios/Runner/Runner.entitlements)
(present) plus a provisioning profile that includes `group.com.example.dvma`.

Every **other** channel still returns `FlutterMethodNotImplemented`, so those Dart
bridges keep their null fallback - **no behavior change**; it just reserves the
channels. To make one *real* on iOS, implement the method there, emit it to os_log
under `DVMA-EVIDENCE`, and allow iOS in that Dart bridge's `isAvailable`. The
Android-only trust boundaries (implicit broadcasts, exported components,
ContentProviders, Binder) have **no iOS equivalent** and should stay
not-implemented - the Dart simulation is the correct representation. The
remaining Tier-C modules are iOS App Intents / Shortcuts / Universal-Link /
WKWebView surfaces that are UI/URL-routing flows without a self-contained OS
probe, so they stay honest in-Dart simulations.

> A per-module breakdown of which iOS module is Tier A / B-real / B-nosim / C
> lives in [`docs/ios_parity_audit.md`](../docs/ios_parity_audit.md),
> generated by `automation/scripts/ios_parity_audit.py` so it stays in sync.

---

## File tree

```text
automation/
├── README.md
├── vuln_manifest.json          # generated by tool/generate.dart (source of truth)
├── scripts/                    # capture harness (record real artifacts) - see scripts/README.md for the full index
│   ├── README.md                # index of every script + OS support
│   ├── lib/common.sh            # shared printers + doc-linked failure output
│   ├── capture_listener.py      # local HTTP/HTTPS flow logger
│   ├── capture_run.sh           # drive walk-all + pull artifacts + report (ATTACKER=1 opt-in)
│   ├── capture_run_ios.sh       # iOS: run RunnerUITests walk + pull sim artifacts -> report-ios.md
│   ├── appium_run_ios.sh        # iOS: boot sim + build + Appium native walk + pull artifacts
│   ├── appium_run_android.sh    # Android: resolve device/JDK + build + Appium native walk + pull artifacts
│   ├── build_capture_report.py  # assemble automation/artifacts/report.md
│   ├── verify_all_modules.sh    # Android-only: per-module PASS/NO-EVIDENCE check
│   ├── demo.sh                  # entry point: demo.sh <otp|broadcast|components>
│   ├── demo_cross_app_otp.sh    # one-command cross-app OTP leak demo (companion attacker)
│   ├── demo_broadcast_ipc.sh    # broadcast-IPC modules demo/verification (companion attacker)
│   └── demo_exported_components.sh # exported-component modules demo/verification (companion attacker)
├── appium/                     # PRIMARY: Node.js + WebdriverIO + Appium
│   ├── package.json
│   ├── .gitignore
│   ├── wdio.shared.conf.js      # base config + driver-flavor selector
│   ├── wdio.android.conf.js     # Android caps (Flutter | UiAutomator2)
│   ├── wdio.ios.conf.js         # iOS caps (Flutter | XCUITest)
│   ├── lib/
│   │   └── dvma.js              # manifest loader + cross-driver helpers
│   └── test/
│       ├── smoke.e2e.js         # launch + search
│       └── walk-all-modules.e2e.js  # expand-all -> search-nav every module -> actions -> evidence -> screenshot
├── espresso/                   # Android native (UiAutomator) source files
│   ├── DvmaSmokeTest.kt
│   └── DvmaWalkAllModulesTest.kt
└── xcuitest/                   # iOS native (XCUITest) - reference copies of
    ├── DVMASmokeUITests.swift      #   the wired-in ios/RunnerUITests/ sources
    └── DVMAWalkAllModulesUITests.swift
```

The XCUITest sources are wired into the Xcode project (parity with `androidTest/`):

```text
ios/
├── Runner/
│   └── DvmaNativeProbes.swift   # MethodChannel seam; dvma/resilience implemented for real, others reserved
└── RunnerUITests/           # RunnerUITests UI-testing target (built by xcodebuild)
    ├── DVMASmokeUITests.swift
    └── DVMAWalkAllModulesUITests.swift
```

The standalone companion attacker app lives outside `automation/`:

```text
companion/
└── dvma-attacker/           # com.dvma.attacker (separate Gradle project)
    ├── README.md
    ├── settings.gradle.kts
    ├── build.gradle.kts
    ├── gradlew / gradle/wrapper/
    └── app/
        ├── build.gradle.kts
        └── src/main/
            ├── AndroidManifest.xml
            └── kotlin/com/dvma/attacker/
                ├── AttackerActivity.kt      # starts the harvest foreground service
                ├── OtpHarvestService.kt     # keeps the runtime receiver alive
                ├── OtpLeakReceiver.kt        # harvests DVMA's unprotected OTP broadcast
                └── AttackerCapture.kt        # logcat + pullable capture file
```

---

## Placeholders to confirm

These defaults were detected from the repo but should be re-verified for your
build/device:

- **`APP_PACKAGE` / `pkg`** - `com.dvma` (Android applicationId).
- **`BUNDLE_ID`** - `com.dvma` (iOS bundle id).
- **`APP_ACTIVITY`** - `.MainActivity` (standard Flutter host; confirm in
  `android/app/src/main/AndroidManifest.xml`).
- **`DEVICE_NAME` / `PLATFORM_VERSION` / `UDID`** - set to match your emulator or
  simulator (`adb devices`, `xcrun simctl list`).
- **`APP_PATH`** - points at the debug artifact by default; override if you build
  elsewhere or test a release/native build.
