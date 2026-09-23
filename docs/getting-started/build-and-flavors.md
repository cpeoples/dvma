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

```sh
# Run every module against a local Ollama instead of any hosted model:
flutter run --dart-define-from-file=config/flavors/dev.json \
  --dart-define=DVMA_LLM_ENDPOINT=http://localhost:11434/v1/chat/completions \
  --dart-define=DVMA_LLM_MODEL=llama3.2:1b
```

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

Android toolchain and dependency versions live in one place,
`gradle/libs.versions.toml`, read by both the app (`android/`) and the companion
attacker (`companion/dvma-attacker/`): AGP, Kotlin, `compileSdk`/`minSdk`/
`targetSdk`, the JVM bytecode target, and the `androidx.test` stack. Bump a
version there and both Gradle builds follow.

A few versions can't read that file because their tools require their own
format, so they're pinned in their native location and kept in step by hand:

| Version | Lives in | Notes |
| --- | --- | --- |
| Gradle wrapper | `android/gradle/wrapper/gradle-wrapper.properties` and the companion's wrapper | Keep both on the `gradle` version noted in the catalog. |
| Flutter SDK | `.tool-versions` | CI's `FLUTTER_VERSION` is checked against this in the lint job, so they can't drift. |
| iOS deployment target / Swift | `ios/Runner.xcodeproj` | Mirrored as `iosDeploymentTarget` / `swift` in the catalog for reference. |
