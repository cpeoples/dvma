## Android emulator, end to end with the automation

No physical phone needed: the Android harnesses (`appium_run_android.sh`,
`verify_all_modules.sh`, `capture_run.sh`, the `demo.sh` demos) treat an emulator
exactly like a device, they resolve whatever `adb` reports in state `device`,
including an `emulator-5554`.

Install the emulator package and a system image (once):

```sh
sdkmanager "emulator" "platform-tools" \
  "system-images;android-34;google_apis;arm64-v8a"   # arm64 host (Apple Silicon)
```

Create an AVD from that image:

```sh
avdmanager create avd -n dvma_api34 -d pixel_7 \
  -k "system-images;android-34;google_apis;arm64-v8a"
```

Boot it headless (no window) and wait until it's fully ready:

```sh
emulator -avd dvma_api34 -no-window -no-snapshot -gpu swiftshader_indirect &
adb wait-for-device
until [ "$(adb shell getprop sys.boot_completed | tr -d '\r')" = 1 ]; do sleep 2; done
```

Confirm `adb` sees it, then run any harness, it auto-selects the emulator:

```sh
adb devices                                   # e.g. emulator-5554   device
automation/scripts/appium_run_android.sh      # build + Appium walk + pull artifacts
```

> `sdkmanager`/`avdmanager`/`emulator` ship with the Android SDK cmdline-tools;
> if they're not on `PATH`, they live under `$ANDROID_HOME/cmdline-tools/latest/bin`
> and `$ANDROID_HOME/emulator`. Set `ANDROID_HOME`/`JAVA_HOME` once (see
> [Prerequisites → environment variables](/getting-started/prerequisites/#host-toolchain))
> so the manual `adb`/`emulator` commands resolve, the harness scripts above
> auto-resolve both, so they work even if your shell profile doesn't set them.
> Use an **x86_64** system image on Intel hosts.


## Install on a physical device, clone → build → `adb install`

End-to-end, from a fresh clone to the app running on a plugged-in Android
phone. (`flutter build apk` drives Gradle/`gradlew` under the hood **and**
injects the DVMA flavor via `--dart-define-from-file`, so it's the correct
entry point, see the [note on `gradlew`](#building-the-apk-with-gradlew-directly)
below.)

0. Prereqs: `flutter doctor` is green for Android, and the phone has USB
   debugging on (Settings ▸ Developer options ▸ USB debugging) and is authorized.
   Clone and generate.

   ```sh
   git clone https://github.com/<your-org>/dvma.git
   cd dvma
   flutter pub get
   dart run tool/generate.dart          # (re)generate registry + router
   ```

1. Confirm the device is visible.

   ```sh
   flutter devices                      # or: adb devices  (should list your phone)
   ```

2. Install to the device. Either build **and** install in one step…

   ```sh
   flutter install --dart-define-from-file=config/flavors/full.json
   ```

   …or build the APK, then install it explicitly with `adb`.

   ```sh
   flutter build apk --release --dart-define-from-file=config/flavors/full.json
   adb install -r build/app/outputs/flutter-apk/app-release.apk
   #   -r reinstalls/keeps data; add -d to target a USB device if an emulator is also up.
   ```

3. Launch it (or just tap the DVMA icon).

   ```sh
   adb shell am start -n com.dvma/.MainActivity
   ```

The APK lands at **`build/app/outputs/flutter-apk/app-release.apk`**
(`app-debug.apk` for a debug build). The `release` build type is signed with
the **debug keystore** (see `android/app/build.gradle.kts`), so it installs on
any device with no extra signing setup, this is intentional for a local
training target, not a store-ready build.

<details>
<summary><strong>Debug APK (faster iteration, debuggable, Frida-friendly)</strong></summary>

For hands-on work you often want the **debug** build instead of release: it's
quicker to produce, ships with `android:debuggable="true"` (so you can attach a
debugger / `run-as` the app), and is the natural target for dynamic-analysis
exercises (Frida, `objection`). Same flavor flag, just `--debug`:

```sh
# Build + install the debug APK in one step
flutter install --debug --dart-define-from-file=config/flavors/dev.json

# Or build it, then install with adb
flutter build apk --debug --dart-define-from-file=config/flavors/dev.json
adb install -r build/app/outputs/flutter-apk/app-debug.apk
```

Notes:

- Debug builds run in **JIT** mode and are larger/slower at runtime than
  release; use release when you're measuring performance or testing
  release-only behavior (e.g. R8/obfuscation, `--split-debug-info`).
- `flutter run --dart-define-from-file=config/flavors/dev.json` is effectively a
  debug build with hot reload attached, the fastest loop while developing.
- Both debug and release install side-by-side is **not** possible here (same
  `applicationId`); `adb install -r` reinstalls over the other.

</details>

<br/>

<details>
<summary id="building-the-apk-with-gradlew-directly"><strong>Building the APK with <code>gradlew</code> directly (advanced)</strong></summary>

DVMA's flavors are **`--dart-define` compile-time configs, not Gradle product
flavors**. A bare `./gradlew assembleRelease` therefore builds an APK **without**
the DVMA flavor wiring (it falls back to the built-in default), because Gradle
never sees the dart-defines. `flutter build apk` is the supported way to inject
them, so prefer it, it drives `gradlew` for you.

If you specifically need the underlying Gradle command (e.g. to plug into an
existing CI pipeline), let Flutter print it and copy it verbatim rather than
hand-encoding the defines:

```sh
flutter build apk --release \
  --dart-define-from-file=config/flavors/full.json --verbose
# The log shows the exact `gradlew ... -Pdart-defines=<base64...>` invocation
# Flutter runs; reuse that line in CI if you must call Gradle yourself.
```

(The `-Pdart-defines` value is a Flutter-internal base64 encoding of each
`key=value`, which is why hand-rolling it is fragile and `flutter build apk` /
`flutter install` are the recommended path.)
</details>
