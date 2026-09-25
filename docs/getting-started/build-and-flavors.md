## Build & run commands

DVMA's application / bundle id is `com.dvma` (the single source of truth is
`config/app.json`; run `dart run tool/sync_app_id.dart` after changing it).
Select a
build flavor with `--dart-define-from-file` (see below):

```sh
# Run on a connected device / emulator (dev flavor = every vuln enabled)
flutter run --dart-define-from-file=config/flavors/dev.json

# Build release binaries
flutter build apk    --dart-define-from-file=config/flavors/full.json
flutter build appbundle --dart-define-from-file=config/flavors/full.json
flutter build ios    --dart-define-from-file=config/flavors/full.json   # macOS + Xcode
```

## Finding your device, serial / id, emulators & simulators

Every install command below targets a device by its **id** (Android calls it a
*serial*, iOS a long hash). List everything Flutter can see:

```sh
flutter devices
# Example rows (the middle column is the id you pass to `-d`):
#   Bob's iPhone (mobile) • 267845a940ad...c0f • ios      • iOS 16.7.16
#   sdk gphone64 arm64    • emulator-5554      • android  • Android 14
#   macOS (desktop)       • macos             • darwin-arm64
```

Then target it explicitly: `flutter run -d <id>` (or `flutter install -d <id>`).

**Android, physical device serial.** Enable *USB debugging* (Settings ▸
Developer options), plug in, authorize the prompt, then:

```sh
adb devices          # lists each serial, e.g. `R58N1234ABC   device`
flutter devices      # same serial appears under the id column
```

**Android, emulator (AVD).** You need at least one AVD image first (created via
Android Studio ▸ *Device Manager*, or the CLI below). Then Flutter/`emulator`
can launch it:

```sh
flutter emulators                       # list AVDs Flutter knows about
flutter emulators --launch <emulator-id>   # boot one, e.g. Pixel_7_API_34
# No AVDs yet? create one from the command line:
sdkmanager "system-images;android-34;google_apis;arm64-v8a"
avdmanager create avd -n Pixel_7_API_34 \
  -k "system-images;android-34;google_apis;arm64-v8a" -d pixel_7
# (sdkmanager/avdmanager ship with the Android SDK cmdline-tools.)
```

**iOS, simulator.** No AVD/creation step and **no code signing** needed. List
and boot with `simctl`, or just let Flutter pick a booted one:

```sh
xcrun simctl list devices available     # all installed simulators + their UDIDs
open -a Simulator                        # opens the default simulator
xcrun simctl boot "iPhone 17"           # or boot a specific model
flutter run -d <udid|"iPhone 17"> --dart-define-from-file=config/flavors/full.json
```

Once your target is booted/connected, use the platform-specific install flow
below.

### First run: one-command bootstrap (recommended)

If you don't already have a device booted, two helper scripts take you from a
fresh checkout to the app running. Each resolves the SDK/tooling, boots a device
(creating an Android AVD on first run), waits for it to finish booting, then
runs the `full` flavor on it:

```sh
automation/scripts/bootstrap_emulator.sh    # Android emulator
automation/scripts/bootstrap_simulator.sh   # iOS Simulator (macOS + Xcode)
```

Both are **self-healing**. A just-crashed Android emulator leaves stale lock
files behind (`hardware-qemu.ini.lock`, `multiinstance.lock`) that make the next
launch die a few seconds in; the script clears them and cold-boots. If the first
`flutter run` fails on a half-written build cache (the Android *"package
identifier or launch activity not found"* / *"No application found for
TargetPlatform"* errors, or an iOS build/pod desync), the script cleans the
Flutter cache (and reinstalls CocoaPods on iOS) and retries once before
surfacing a real error.

Useful overrides: `FLAVOR=config/flavors/dev.json`, `SKIP_RUN=1` (boot only),
`AVD=<name>` / `API=<level>` (Android), `DEVICE_NAME="iPhone 15"` / `UDID=<udid>`
(iOS).

**All configuration lives under `config/`**, there are no scattered `.env`
files or per-module config. Flavors are `--dart-define-from-file` JSON files:

| Flavor | File | Purpose |
| -------- | ------ | --------- |
| `dev` | `config/flavors/dev.json` | Everything enabled; for building new modules |
| `training` | `config/flavors/training.json` | Curated, self-contained subset for classroom use |
| `full` | `config/flavors/full.json` | Every vulnerability across every category |

At startup, `lib/app_config.dart` parses the active flavor once into an
immutable `AppConfig`. `lib/vulnerability_registry.dart` (generated) consults it
so the UI surfaces **only** the enabled set. Toggle categories with
`DVMA_ENABLED_CATEGORIES` and deny individual vulns with `DVMA_DISABLED_VULNS`.

### Configuration reference, one override surface

Every build-time value the app reads, the app id, module gating, the network
endpoints real modules talk to, and the live-LLM backends, is declared in a
single file, `lib/core/config/dvma_env.dart`. Nothing else in the app calls
`String.fromEnvironment`, so that file is the one place to look or change. Set
any of them from a flavor JSON or ad-hoc with `--dart-define=<KEY>=<value>`:

| `--dart-define` key | Default | What it controls |
| --------------------- | --------- | ------------------ |
| `DVMA_APP_ID` | `com.dvma` | Package / bundle id (mirrors the Android `applicationId`). |
| `DVMA_PLATFORM` | detected | Force the module catalog to `android` or `ios`. |
| `DVMA_ENABLE_ALL` | `true` | Enable every category regardless of the list below. |
| `DVMA_ENABLED_CATEGORIES` | all | Comma-separated categories to enable. |
| `DVMA_DISABLED_VULNS` | *(none)* | Comma-separated vuln ids to force off. |
| `DVMA_VERBOSE_LOGGING` | `true` | Emit the intentionally-leaky module logs. |
| `DVMA_CAPTURE_BASE` | `http://10.0.2.2:8080` | Base URL the network modules send real traffic to (the emulator's host-loopback capture listener). |
| `DVMA_LLM_API_BASE` | `http://10.0.2.2:8080` | Base URL for the in-app assistant's mock backend. |
| `DVMA_INSECURE_UPDATE_URL` | `…/model/update` | Unauthenticated model-update URL for the supply-chain demo. |

The AI modules make a **real** model call out of the box, trying each backend in
order and falling back to the next: your custom endpoint (if set) →
OpenRouter → keyless [Pollinations](https://text.pollinations.ai). Point them
anywhere without a code change:

| `--dart-define` key | Default | What it controls |
| --------------------- | --------- | ------------------ |
| `DVMA_LLM_LIVE` | `true` | Master switch; `false` forces the fully-offline mock. |
| `DVMA_LLM_ENDPOINT` | *(none)* | A custom OpenAI-compatible endpoint (e.g. a local Ollama/LM Studio); tried first when set. |
| `DVMA_LLM_MODEL` | *(none)* | Model id for the custom endpoint. |
| `DVMA_LLM_KEY` | *(none)* | Bearer token for the custom endpoint (local servers usually need none). |
| `DVMA_OPENROUTER_KEY` | *(empty)* | OpenRouter API key. Empty by default - no credential is committed to source. Supply your own throwaway key via `--dart-define`; a key in source would itself be a DVMA anti-pattern. |
| `DVMA_OPENROUTER_MODEL` | `liquid/lfm-2.5-2.6b:free` | Small free model that reliably exhibits the prompt-injection behavior the demos need. |
| `DVMA_OPENROUTER_MODELS` | *(empty)* | Optional comma-separated rotation list. When set, each model is tried in order per request, so if the primary is rate-limited (429) or down, the call falls through to the next before dropping to the keyless tier. Empty = use `DVMA_OPENROUTER_MODEL` alone. |

```sh
# Run every module against a local Ollama instead of any hosted model:
flutter run --dart-define-from-file=config/flavors/dev.json \
  --dart-define=DVMA_LLM_ENDPOINT=http://localhost:11434/v1/chat/completions \
  --dart-define=DVMA_LLM_MODEL=llama3.2:1b
```

For the most reliable live demo, supply your own OpenRouter key at build time.
With no key the modules fall back to the keyless Pollinations tier, which is
rate-limited and more likely to refuse - when every live backend is exhausted
the call drops to the offline mock. A free-tier key on the default
`liquid/lfm-2.5-2.6b:free` model leaks and obeys injection far more
consistently:

```sh
flutter run --dart-define-from-file=config/flavors/dev.json \
  --dart-define=DVMA_OPENROUTER_KEY=sk-or-...
```

Each AI module's evidence panel shows a **model backend** line (`openrouter
(…)`, `pollinations (keyless)`, or `offline-mock`), so you can always tell which
backend actually answered and whether a demo fell back rather than hitting the
model you intended.

## Per-platform modules (Android vs iOS)

Many vulnerabilities are platform-specific: Android-only ones (exported
components, `ContentProvider`/Intent IPC, `MediaProjection`, IME, Binder) and
iOS-only ones (Keychain access-groups, Siri/App Intents, Shortcuts, WKWebView
local-file reads, ATT). The rest are **shared** classes that simply surface
through different APIs on each OS.

Each registry entry carries an optional `platforms:` list (`[android]`,
`[ios]`, or omitted = shared/both) and an optional `platform_note` describing
the per-OS difference (e.g. *Android `addJavascriptInterface`; iOS
`WKScriptMessageHandler`*). `AppConfig` detects the running OS and **hard-filters
the catalog**: the Android build lists only Android + shared modules, and the
iOS build only iOS + shared. Override the detected platform at build time with
`--dart-define=DVMA_PLATFORM=ios|android` (useful for cross-building or tests).
The docs site shows an Android and/or iOS chip on every module (a shared module
shows both).

## Toolchain versions (single source of truth)

Almost every Android version lives in one file, **`gradle/libs.versions.toml`**,
read by both the app (`android/`) and the companion attacker
(`companion/dvma-attacker/`). Its `[versions]` keys are:

| Key | Controls |
| --- | --- |
| `agp` | Android Gradle Plugin (both projects) |
| `kotlin` | Kotlin Gradle plugin (both projects) |
| `compileSdk`, `minSdk`, `targetSdk` | SDK levels |
| `jvmTarget` | Java/Kotlin bytecode target |
| `androidxTest*` | the opt-in Espresso/UiAutomator deps |
| `androidxCoreKtx`, `androidxAppcompat` | companion runtime deps |
| `gradle`, `iosDeploymentTarget`, `swift` | reference only (see below) |

Edit the key and both Gradle builds follow. No Android version is authored
anywhere else.

### The three versions the catalog can't apply itself

These tools need their own file format, so the catalog only *records* them and
you edit them in the file below:

| Version | Edit here | Kept in step by |
| --- | --- | --- |
| Gradle wrapper | `android/gradle/wrapper/gradle-wrapper.properties` **and** `companion/dvma-attacker/gradle/wrapper/gradle-wrapper.properties` (both, identical) | Match the catalog's `gradle` key; Dependabot is told to ignore the wrapper so it can't re-drift them. |
| Flutter SDK | `.tool-versions` | `env.FLUTTER_VERSION` in `.github/workflows/ci.yml` and `release.yml`; the lint job fails if they disagree. |
| iOS deployment target / Swift | `ios/Runner.xcodeproj/project.pbxproj` (`IPHONEOS_DEPLOYMENT_TARGET`, `SWIFT_VERSION`) | Mirror the catalog's `iosDeploymentTarget` / `swift` keys. |

### Bumping coupled versions

- **AGP:** change `agp` in the catalog, then set the matching Gradle version in
  **both** wrapper files (AGP 9.1 needs Gradle 9.3.1; see the
  [AGP/Gradle table](https://developer.android.com/build/releases/about-agp)),
  update the `gradle` key to match, and confirm the AGP is within what the pinned
  Flutter supports.
- **Flutter:** change `.tool-versions`, then set the same value in
  `env.FLUTTER_VERSION` in `ci.yml` and `release.yml` (CI enforces the match).
