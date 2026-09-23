#!/usr/bin/env bash
#
# DVMA Appium walk harness (Android device / emulator).
#
# The Android analogue of appium_run_ios.sh. It drives the SAME app with
# Appium + WebdriverIO through the UiAutomator2 driver so you can run the
# identical "walk every module" flow on Android as on iOS.
#
# It:
#   1. resolves adb and a target device (physical or emulator),
#   2. builds the DVMA "full" debug APK (unless SKIP_BUILD=1),
#   3. installs it and primes the app container (launch, then force-stop),
#   4. starts a local Appium server (if one isn't already running),
#   5. runs the WDIO walk spec with DVMA_DRIVER=native (UiAutomator2), which
#      exercises every module (expand-all -> search-nav -> controls -> actions
#      -> evidence),
#   6. pulls the evidence artifacts from the app's external files dir and the
#      DVMA-EVIDENCE logcat stream, alongside the per-module WDIO screenshots.
#
# The app's evidence sink writes files under the app's external files dir
#   /sdcard/Android/data/<pkg>/files/dvma-artifacts/<vulnId>.txt
# which `adb pull` can read without root, and mirrors every record to logcat
# under the "DVMA-EVIDENCE" tag.
#
# FOR AUTHORIZED TRAINING USE ONLY. Use a disposable/test device.
#
# Usage (from repo root):
#   automation/scripts/appium_run_android.sh
#
# Env overrides:
#   APP_PACKAGE  app applicationId        (default com.dvma)
#   APP_ACTIVITY launch activity          (default .MainActivity)
#   SERIAL       target device serial     (default: the single connected device)
#   ADB          path to adb              (default: PATH -> ANDROID_HOME -> SDK)
#   FLAVOR       dart-define-from-file     (default config/flavors/full.json)
#   DVMA_DRIVER  native | flutter         (default native - full-fidelity walk)
#   SPEC         smoke | walk             (default walk)
#   APPIUM_PORT  appium server port       (default 4723)
#   ARTIFACTS    output dir               (default automation/artifacts/android-appium)
#   SKIP_BUILD   set to 1 to reuse an existing APK
set -euo pipefail

APP_PACKAGE="${APP_PACKAGE:-com.dvma}"
APP_ACTIVITY="${APP_ACTIVITY:-.MainActivity}"
FLAVOR="${FLAVOR:-config/flavors/full.json}"
DVMA_DRIVER="${DVMA_DRIVER:-native}"
SPEC="${SPEC:-walk}"
APPIUM_PORT="${APPIUM_PORT:-4723}"
ARTIFACTS="${ARTIFACTS:-automation/artifacts/android-appium}"

APP_PATH="build/app/outputs/flutter-apk/app-debug.apk"
APPIUM_DIR="automation/appium"
SINK_SUBDIR="dvma-artifacts"
LOG_TAG="DVMA-EVIDENCE"
FILES_DIR="$ARTIFACTS/files"
LOGCAT_RAW="$ARTIFACTS/logcat_evidence.txt"
APPIUM_LOG="$ARTIFACTS/appium-server.log"

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

command -v node    >/dev/null 2>&1 || die "node not found - install Node.js 18+ (e.g. brew install node)" "getting-started/prerequisites/#host-toolchain"
command -v flutter >/dev/null 2>&1 || die "flutter not found on PATH - install Flutter" "getting-started/installing-flutter/"
mkdir -p "$FILES_DIR"

# JDK resolution (Gradle needs a real JRE; macOS /usr/bin/java is a stub).
# Only set JAVA_HOME if it isn't already pointing at a working java. Prefer a
# JDK 17 (Android Gradle Plugin's supported LTS), then any Homebrew openjdk,
# then the Android Studio bundled runtime.
if [[ -z "${JAVA_HOME:-}" || ! -x "${JAVA_HOME:-}/bin/java" ]]; then
  for jdk in \
    "/opt/homebrew/opt/openjdk@17" \
    "/usr/local/opt/openjdk@17" \
    "/opt/homebrew/opt/openjdk" \
    "/usr/local/opt/openjdk" \
    "/Applications/Android Studio.app/Contents/jbr/Contents/Home" \
    "$(/usr/libexec/java_home 2>/dev/null || true)"; do
    if [[ -n "$jdk" && -x "$jdk/bin/java" ]]; then export JAVA_HOME="$jdk"; break; fi
  done
fi
[[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]] \
  || die "no Java runtime found (Gradle needs a JDK). Install one, e.g.: brew install openjdk@17 - then set JAVA_HOME" "getting-started/prerequisites/#host-toolchain"
export PATH="$JAVA_HOME/bin:$PATH"
note "JAVA_HOME=$JAVA_HOME"

# Clear last run's WDIO screenshots so the collected count reflects this run.
rm -f "$APPIUM_DIR/artifacts/"*.png 2>/dev/null || true
rm -rf "$ARTIFACTS/screenshots" 2>/dev/null || true

# adb resolution (portable; same technique as verify_all_modules.sh)
resolve_adb() {
  if [[ -n "${ADB:-}" && -x "${ADB:-}" ]]; then echo "$ADB"; return; fi
  if command -v adb >/dev/null 2>&1; then command -v adb; return; fi
  local sdk cand
  for sdk in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" \
             "$HOME/Library/Android/sdk" "$HOME/Android/Sdk" \
             "/opt/homebrew/share/android-commandlinetools" \
             "/usr/local/share/android-commandlinetools" \
             "/usr/lib/android-sdk"; do
    [[ -n "$sdk" ]] || continue
    cand="$sdk/platform-tools/adb"
    [[ -x "$cand" ]] && { echo "$cand"; return; }
  done
  return 1
}
ADB_BIN="$(resolve_adb || true)"
[[ -n "$ADB_BIN" ]] || die "adb not found (set ADB=, ANDROID_HOME, or add platform-tools to PATH)" "getting-started/prerequisites/#host-toolchain"

# Resolve target device
say "Resolving device"
"$ADB_BIN" start-server >/dev/null 2>&1 || true
resolve_serial() {
  if [[ -n "${SERIAL:-}" ]]; then echo "$SERIAL"; return; fi
  "$ADB_BIN" devices | awk 'NR>1 && $2=="device" {print $1}' | head -1
}
SERIAL="$(resolve_serial || true)"
[[ -n "$SERIAL" ]] || die "no device in state 'device' (check: $ADB_BIN devices; authorize the USB prompt, or boot an emulator)" "getting-started/prerequisites/#android-device-physical"
ADB=("$ADB_BIN" -s "$SERIAL")
note "adb: $ADB_BIN"
note "device: $SERIAL ($("${ADB[@]}" shell getprop ro.product.model 2>/dev/null | tr -d '\r'), Android $("${ADB[@]}" shell getprop ro.build.version.release 2>/dev/null | tr -d '\r'))"
ok "device ready: $SERIAL"

# The UiAutomator2 driver (inside the Appium server) needs ANDROID_HOME to find
# its own adb. Derive the SDK root from the resolved adb (…/platform-tools/adb).
if [[ -z "${ANDROID_HOME:-}" && -z "${ANDROID_SDK_ROOT:-}" ]]; then
  ANDROID_HOME="$(cd "$(dirname "$ADB_BIN")/.." && pwd)"
  export ANDROID_HOME
  export ANDROID_SDK_ROOT="$ANDROID_HOME"
  note "ANDROID_HOME=$ANDROID_HOME"
fi

# Ensure Appium + UiAutomator2 driver are available
say "Checking Appium"
APPIUM_BIN=""
if command -v appium >/dev/null 2>&1; then
  APPIUM_BIN="appium"
elif [[ -x "$APPIUM_DIR/node_modules/.bin/appium" ]]; then
  APPIUM_BIN="$APPIUM_DIR/node_modules/.bin/appium"
fi
if [[ -z "$APPIUM_BIN" ]]; then
  bad "appium not found. Install it (either globally or into $APPIUM_DIR):"
  note "  npm i -g appium                       # or: (cd $APPIUM_DIR && npm i appium)"
  note "  appium driver install uiautomator2    # native Android driver"
  note "  appium driver install flutter         # optional Flutter driver"
  docs "getting-started/automation/"
  exit 1
fi
# When Appium was installed project-locally, its drivers live under a repo-local
# APPIUM_HOME so they don't touch the user's global setup. Point the server at it.
if [[ -z "${APPIUM_HOME:-}" && -d "$APPIUM_DIR/.appium" ]]; then
  APPIUM_HOME="$(cd "$APPIUM_DIR/.appium" && pwd)"
  export APPIUM_HOME
  note "APPIUM_HOME=$APPIUM_HOME"
fi
note "appium: $APPIUM_BIN ($("$APPIUM_BIN" --version 2>/dev/null || echo '?'))"
if ! "$APPIUM_BIN" driver list --installed 2>&1 | grep -qi uiautomator2; then
  bad "appium uiautomator2 driver not installed - run: $APPIUM_BIN driver install uiautomator2"
  docs "getting-started/automation/"
  exit 1
fi
ok "uiautomator2 driver present"

# Build the debug APK
if [[ "${SKIP_BUILD:-0}" == "1" && -f "$APP_PATH" ]]; then
  note "SKIP_BUILD=1 - reusing $APP_PATH"
else
  say "Building DVMA (debug APK) with flavor $FLAVOR"
  flutter build apk --debug --dart-define-from-file="$FLAVOR"
fi
[[ -f "$APP_PATH" ]] || { bad "expected APK not found at $APP_PATH"; exit 1; }
ok "apk built: $APP_PATH"

# Install + prime the container so the app's external files dir exists, then
# force-stop; Appium will reinstall/relaunch under its own session.
say "Priming app container"
"${ADB[@]}" install -r -g "$APP_PATH" >/dev/null 2>&1 || "${ADB[@]}" install -r "$APP_PATH" >/dev/null 2>&1 || true
"${ADB[@]}" shell monkey -p "$APP_PACKAGE" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
sleep 2
"${ADB[@]}" shell am force-stop "$APP_PACKAGE" >/dev/null 2>&1 || true
"${ADB[@]}" logcat -c >/dev/null 2>&1 || true

# Start Appium (unless one is already listening)
APPIUM_PID=""
if curl -sf "http://127.0.0.1:${APPIUM_PORT}/status" >/dev/null 2>&1; then
  note "reusing Appium already listening on :$APPIUM_PORT"
else
  say "Starting Appium on :$APPIUM_PORT"
  "$APPIUM_BIN" --port "$APPIUM_PORT" --log-timestamp --log-no-colors >"$APPIUM_LOG" 2>&1 &
  APPIUM_PID=$!
  for _ in $(seq 1 30); do
    curl -sf "http://127.0.0.1:${APPIUM_PORT}/status" >/dev/null 2>&1 && break
    sleep 1
  done
  curl -sf "http://127.0.0.1:${APPIUM_PORT}/status" >/dev/null 2>&1 \
    || { bad "Appium did not come up - see $APPIUM_LOG"; [[ -n "$APPIUM_PID" ]] && kill "$APPIUM_PID" 2>/dev/null; exit 1; }
  ok "appium up (pid $APPIUM_PID)"
fi
cleanup() { [[ -n "$APPIUM_PID" ]] && kill "$APPIUM_PID" 2>/dev/null || true; }
trap cleanup EXIT

# Install WDIO deps if needed
if [[ ! -d "$APPIUM_DIR/node_modules" ]]; then
  say "Installing WDIO dependencies"
  (cd "$APPIUM_DIR" && npm install --silent)
fi

# Run the walk
case "$SPEC" in
  smoke) SPEC_FILE="./test/smoke.e2e.js" ;;
  walk)  SPEC_FILE="./test/walk-all-modules.e2e.js" ;;
  *)     SPEC_FILE="$SPEC" ;;
esac
say "Running Appium Android $SPEC (DVMA_DRIVER=$DVMA_DRIVER)"
set +e
( cd "$APPIUM_DIR" \
  && APP_PATH="$(cd ../.. && pwd)/$APP_PATH" \
     APP_PACKAGE="$APP_PACKAGE" \
     APP_ACTIVITY="$APP_ACTIVITY" \
     UDID="$SERIAL" \
     DVMA_DRIVER="$DVMA_DRIVER" \
     APPIUM_PORT="$APPIUM_PORT" \
     MOCHA_TIMEOUT="${MOCHA_TIMEOUT:-1800000}" \
     DVMA_MODULE_IDS="${DVMA_MODULE_IDS:-}" \
     npx wdio run ./wdio.android.conf.js --spec "$SPEC_FILE" )
WDIO_RC=$?
set -e
[[ $WDIO_RC -eq 0 ]] && ok "walk finished (rc=0)" || bad "walk reported failures (rc=$WDIO_RC)"

# Collect artifacts from the app's external files dir + logcat
say "Collecting evidence artifacts"
SINK_DIR="/sdcard/Android/data/$APP_PACKAGE/files/$SINK_SUBDIR"
if "${ADB[@]}" shell "ls $SINK_DIR" >/dev/null 2>&1; then
  "${ADB[@]}" pull "$SINK_DIR" "$FILES_DIR" >/dev/null 2>&1 || true
  # adb pull nests the dir; flatten any .txt into FILES_DIR.
  find "$FILES_DIR" -name '*.txt' -mindepth 2 -exec mv -f {} "$FILES_DIR/" \; 2>/dev/null || true
  COUNT="$(find "$FILES_DIR" -name '*.txt' | wc -l | tr -d ' ')"
  ok "pulled $COUNT evidence file(s) -> $FILES_DIR"
else
  note "no evidence dir on device ($SINK_DIR)"
fi
# WDIO wrote per-module PNGs into automation/appium/artifacts/.
if [[ -d "$APPIUM_DIR/artifacts" ]]; then
  mkdir -p "$ARTIFACTS/screenshots"
  cp -f "$APPIUM_DIR/artifacts/"*.png "$ARTIFACTS/screenshots/" 2>/dev/null || true
  SHOTS="$(find "$ARTIFACTS/screenshots" -name '*.png' | wc -l | tr -d ' ')"
  ok "copied $SHOTS screenshot(s) -> $ARTIFACTS/screenshots"
fi
"${ADB[@]}" logcat -d -s "$LOG_TAG:*" >"$LOGCAT_RAW" 2>/dev/null || true
if [[ -s "$LOGCAT_RAW" ]]; then
  LINES="$(grep -c "$LOG_TAG" "$LOGCAT_RAW" 2>/dev/null || echo 0)"
  ok "captured $LINES logcat evidence line(s) -> $LOGCAT_RAW"
fi

say "Done"
note "artifacts: $ARTIFACTS"
exit "$WDIO_RC"
