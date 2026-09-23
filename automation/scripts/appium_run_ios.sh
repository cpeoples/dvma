#!/usr/bin/env bash
#
# DVMA Appium walk harness (iOS Simulator OR physical device).
#
# The Appium analogue of capture_run_ios.sh (which drives the native XCUITest
# RunnerUITests target). This one drives the SAME app with Appium + WebdriverIO
# so you can run the identical "walk every module" flow through a standard,
# cross-platform mobile-automation stack instead of xcodebuild - and, like the
# Android harness (appium_run_android.sh), it runs on BOTH a Simulator and a
# real device.
#
# TARGET SELECTION (auto, mirrors the Android script):
#   - If a physical iPhone/iPad is attached (idevice_id -l) and no simulator was
#     forced, the harness runs in DEVICE mode. Force either way with DEVICE=1/0.
#
# SIMULATOR mode:
#   1. boots a Simulator, disables the hardware keyboard,
#   2. builds the DVMA "full" .app for the simulator (debug),
#   3. installs + primes the container, then hands off to Appium,
#   4. pulls artifacts from the Mac-side simulator container + os_log.
#
# DEVICE mode (needs a jailbroken device for the artifact pull; see docs):
#   1. resolves the attached device UDID (idevice_id),
#   2. builds a SIGNED device .app (debug, no --simulator) using your
#      ios/Flutter/Signing.xcconfig team,
#   3. installs it with ideviceinstaller and primes the container,
#   4. hands off to Appium (XCUITest signs+installs WebDriverAgent for your team),
#   5. pulls artifacts over SSH/scp from the app's Documents container
#      (/var/mobile/Containers/Data/Application/<UUID>/Documents/dvma-artifacts)
#      plus the device os_log - reusing the same conventions as
#      docs/device-access/ios/verify.md.
#
# The app's evidence sink writes Documents/dvma-artifacts/<vulnId>.txt on iOS
# and mirrors every record to os_log under "DVMA-EVIDENCE".
#
# FOR AUTHORIZED TRAINING USE ONLY. Run on a disposable Simulator or test device.
#
# Usage (from repo root):
#   automation/scripts/appium_run_ios.sh                 # auto: device if attached, else sim
#   DEVICE=0 automation/scripts/appium_run_ios.sh        # force Simulator
#   DEVICE=1 automation/scripts/appium_run_ios.sh        # force attached device
#   DEVICE=1 DEVICE_IP=192.168.0.42 automation/scripts/appium_run_ios.sh
#
# Env overrides:
#   DEVICE       1=physical device, 0=simulator (default: auto-detect)
#   BUNDLE_ID    app bundle id            (default com.dvma)
#   UDID         target udid              (default: attached device / booted sim)
#   DEVICE_NAME  simulator to boot if none (default "iPhone 17")
#   DEVICE_IP    device IP for the SSH pull (default: auto-discover on the LAN)
#   SSH_USER     device ssh user          (default mobile - rootless jailbreak)
#   FLAVOR       dart-define-from-file    (default config/flavors/full.json)
#   DVMA_DRIVER  native | flutter         (default native - full-fidelity walk)
#   SPEC         smoke | walk             (default walk)
#   APPIUM_PORT  appium server port       (default 4723)
#   ARTIFACTS    output dir               (default automation/artifacts/ios-appium)
#   SKIP_BUILD   set to 1 to reuse an existing .app build
set -euo pipefail

BUNDLE_ID="${BUNDLE_ID:-com.dvma}"
DEVICE_NAME="${DEVICE_NAME:-iPhone 17}"
SSH_USER="${SSH_USER:-mobile}"
FLAVOR="${FLAVOR:-config/flavors/full.json}"
DVMA_DRIVER="${DVMA_DRIVER:-native}"
SPEC="${SPEC:-walk}"
APPIUM_PORT="${APPIUM_PORT:-4723}"
ARTIFACTS="${ARTIFACTS:-automation/artifacts/ios-appium}"

APPIUM_DIR="automation/appium"
SINK_SUBDIR="dvma-artifacts"
LOG_NAME="DVMA-EVIDENCE"
FILES_DIR="$ARTIFACTS/files"
OSLOG_RAW="$ARTIFACTS/oslog_evidence.txt"
APPIUM_LOG="$ARTIFACTS/appium-server.log"

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

command -v xcrun >/dev/null 2>&1 || die "xcrun not found - install the full Xcode app (not just Command Line Tools)" "getting-started/prerequisites/#host-toolchain"
command -v node  >/dev/null 2>&1 || die "node not found - install Node.js 18+ (e.g. brew install node)" "getting-started/prerequisites/#host-toolchain"
command -v flutter >/dev/null 2>&1 || die "flutter not found on PATH - install Flutter" "getting-started/installing-flutter/"
mkdir -p "$FILES_DIR"

# Resolve target mode: physical DEVICE vs Simulator (auto by default). Mirrors
# the Android harness, which just uses whatever `adb devices` shows.
attached_ios_udid() { command -v idevice_id >/dev/null 2>&1 && idevice_id -l 2>/dev/null | head -1; }
if [[ -z "${DEVICE:-}" ]]; then
  if [[ -n "$(attached_ios_udid || true)" ]]; then DEVICE=1; else DEVICE=0; fi
fi
if [[ "$DEVICE" == "1" ]]; then
  APP_PATH="build/ios/iphoneos/Runner.app"
  note "target: PHYSICAL DEVICE"
else
  APP_PATH="build/ios/iphonesimulator/Runner.app"
  note "target: SIMULATOR"
fi

# Ensure Appium + drivers are available
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
  note "  appium driver install xcuitest        # native iOS driver"
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
if ! "$APPIUM_BIN" driver list --installed 2>&1 | grep -qi xcuitest; then
  bad "appium xcuitest driver not installed - run: $APPIUM_BIN driver install xcuitest"
  docs "getting-started/automation/"
  exit 1
fi
ok "xcuitest driver present"

# Resolve target + build + prime the app container
if [[ "$DEVICE" == "0" ]]; then
  # Simulator branch: resolve/boot a Simulator (mirrors capture_run_ios.sh).
  say "Resolving Simulator"
  resolve_udid() {
    if [[ -n "${UDID:-}" ]]; then echo "$UDID"; return; fi
    local booted
    booted="$(xcrun simctl list devices booted -j 2>/dev/null \
      | python3 -c 'import json,sys; d=json.load(sys.stdin)["devices"];
[print(x["udid"]) for v in d.values() for x in v if x.get("state")=="Booted"]' \
      | head -1)"
    if [[ -n "$booted" ]]; then echo "$booted"; return; fi
    xcrun simctl list devices available -j 2>/dev/null \
      | python3 -c 'import json,sys,os; d=json.load(sys.stdin)["devices"]; name=os.environ["DEVICE_NAME"];
cands=[x["udid"] for v in d.values() for x in v if x.get("isAvailable") and x["name"]==name];
print(cands[0] if cands else "")' | head -1
  }
  UDID="$(DEVICE_NAME="$DEVICE_NAME" resolve_udid || true)"
  [[ -n "$UDID" ]] || { bad "no Simulator found (set UDID= or a valid DEVICE_NAME; see: xcrun simctl list devices)"; exit 1; }
  note "simulator udid: $UDID"

  device_state() {
    xcrun simctl list devices -j | UDID="$UDID" python3 -c 'import json,sys,os;u=os.environ["UDID"];d=json.load(sys.stdin)["devices"];
print(next((x["state"] for v in d.values() for x in v if x["udid"]==u), "Unknown"))' 2>/dev/null || echo Unknown
  }
  if [[ "$(device_state)" != "Booted" ]]; then
    note "booting simulator…"
    xcrun simctl boot "$UDID" 2>/dev/null || true
  fi
  open -a Simulator --args -CurrentDeviceUDID "$UDID" 2>/dev/null || open -a Simulator 2>/dev/null || true
  xcrun simctl bootstatus "$UDID" -b >/dev/null 2>&1 || true
  [[ "$(device_state)" == "Booted" ]] || { bad "simulator $UDID did not reach Booted"; exit 1; }
  ok "simulator booted: $UDID"

  # Show the software keyboard (hardware keyboard "connected" breaks text entry).
  xcrun simctl spawn "$UDID" defaults write -g AppleKeyboardsAutomaticKeyboardEnabled -bool true >/dev/null 2>&1 || true
  defaults write com.apple.iphonesimulator ConnectHardwareKeyboard -bool false >/dev/null 2>&1 || true

  # Build the simulator .app
  if [[ "${SKIP_BUILD:-0}" == "1" && -d "$APP_PATH" ]]; then
    note "SKIP_BUILD=1 - reusing $APP_PATH"
  else
    say "Building DVMA (debug, simulator) with flavor $FLAVOR"
    flutter build ios --debug --simulator --dart-define-from-file="$FLAVOR"
  fi
  [[ -d "$APP_PATH" ]] || { bad "expected app not found at $APP_PATH"; exit 1; }
  ok "app built: $APP_PATH"

  # Install + launch once so the container exists, then terminate; Appium will
  # relaunch it under its own session.
  say "Priming app container"
  xcrun simctl install "$UDID" "$APP_PATH" >/dev/null 2>&1 || true
  xcrun simctl launch "$UDID" "$BUNDLE_ID" >/dev/null 2>&1 || true
  sleep 2
  xcrun simctl terminate "$UDID" "$BUNDLE_ID" >/dev/null 2>&1 || true
else
  # Physical device branch.
  say "Resolving device"
  command -v idevice_id      >/dev/null 2>&1 || die "idevice_id not found - brew install libimobiledevice" "device-access/ios/verify/"
  command -v ideviceinstaller >/dev/null 2>&1 || die "ideviceinstaller not found - brew install ideviceinstaller" "device-access/ios/install/"
  UDID="${UDID:-$(attached_ios_udid || true)}"
  [[ -n "$UDID" ]] || { bad "no iOS device attached (check: idevice_id -l; trust the USB prompt)"; docs "device-access/ios/verify/"; exit 1; }
  note "device udid: $UDID ($(ideviceinfo -u "$UDID" -k ProductType 2>/dev/null || echo '?'), iOS $(ideviceinfo -u "$UDID" -k ProductVersion 2>/dev/null || echo '?'))"

  # Signing team for the device build + WebDriverAgent (Appium re-signs WDA).
  XCODE_ORG_ID="${XCODE_ORG_ID:-$(sed -n 's/^[[:space:]]*DEVELOPMENT_TEAM[[:space:]]*=[[:space:]]*//p' ios/Flutter/Signing.xcconfig 2>/dev/null | tr -d '[:space:]')}"
  [[ -n "$XCODE_ORG_ID" ]] || die "no signing team - set XCODE_ORG_ID or ios/Flutter/Signing.xcconfig (DEVELOPMENT_TEAM)" "getting-started/ci-and-releases/"
  note "signing team: $XCODE_ORG_ID"

  # Build a SIGNED device .app. The native (XCUITest) driver reads iOS
  # accessibility ids and works against a PROFILE build - which, unlike a debug
  # build on a real device, doesn't wait for a debugger or show the Flutter
  # "Debug" launch screen (so the app UI actually renders). The flutter driver
  # needs the Dart VM service, so it falls back to a debug build.
  if [[ "$DVMA_DRIVER" == "flutter" ]]; then IOS_BUILD_MODE="debug"; else IOS_BUILD_MODE="${IOS_BUILD_MODE:-profile}"; fi
  if [[ "${SKIP_BUILD:-0}" == "1" && -d "$APP_PATH" ]]; then
    note "SKIP_BUILD=1 - reusing $APP_PATH"
  else
    say "Building DVMA ($IOS_BUILD_MODE, device) with flavor $FLAVOR"
    flutter build ios "--$IOS_BUILD_MODE" --dart-define-from-file="$FLAVOR"
  fi
  [[ -d "$APP_PATH" ]] || { bad "expected app not found at $APP_PATH (device signing may have failed - open ios/Runner.xcworkspace once to let Xcode provision)"; exit 1; }
  ok "app built: $APP_PATH"

  # Install + prime the container so Documents/dvma-artifacts exists.
  say "Priming app container"
  ideviceinstaller -u "$UDID" -i "$APP_PATH" >/dev/null 2>&1 \
    || note "ideviceinstaller reported a warning (Appium will (re)install under its own session)"

  # WDA signing caps for the WDIO config.
  export XCODE_ORG_ID
  export WDA_BUNDLE_ID="${WDA_BUNDLE_ID:-com.dvma.wda}"
fi

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
# The full walk runs every module in one Mocha test. A physical device is much
# slower than the Simulator (per-module search/open/action/recover), and there
# are ~160+ modules, so give the device 90 min and the Simulator 40 min by
# default. Override either with MOCHA_TIMEOUT=<ms>.
if [[ "$SPEC" == "walk" ]]; then
  [[ "$DEVICE" == "1" ]] && DEFAULT_MOCHA_TIMEOUT=5400000 || DEFAULT_MOCHA_TIMEOUT=2400000
else
  DEFAULT_MOCHA_TIMEOUT=600000
fi
say "Running Appium iOS $SPEC (DVMA_DRIVER=$DVMA_DRIVER, DEVICE=$DEVICE)"
set +e
( cd "$APPIUM_DIR" \
  && APP_PATH="$(cd ../.. && pwd)/$APP_PATH" \
     BUNDLE_ID="$BUNDLE_ID" \
     UDID="$UDID" \
     DEVICE="$DEVICE" \
     XCODE_ORG_ID="${XCODE_ORG_ID:-}" \
     WDA_BUNDLE_ID="${WDA_BUNDLE_ID:-}" \
     USE_PREBUILT_WDA="${USE_PREBUILT_WDA:-}" \
     DVMA_DRIVER="$DVMA_DRIVER" \
     APPIUM_PORT="$APPIUM_PORT" \
     MOCHA_TIMEOUT="${MOCHA_TIMEOUT:-$DEFAULT_MOCHA_TIMEOUT}" \
     DVMA_MODULE_IDS="${DVMA_MODULE_IDS:-}" \
     npx wdio run ./wdio.ios.conf.js --spec "$SPEC_FILE" )
WDIO_RC=$?
set -e
[[ $WDIO_RC -eq 0 ]] && ok "walk finished (rc=0)" || bad "walk reported failures (rc=$WDIO_RC)"

# Collect artifacts (branch by target)
say "Collecting evidence artifacts"
if [[ "$DEVICE" == "0" ]]; then
  # Simulator branch: read the Mac-side container + os_log.
  CONTAINER="$(xcrun simctl get_app_container "$UDID" "$BUNDLE_ID" data 2>/dev/null || true)"
  if [[ -n "$CONTAINER" && -d "$CONTAINER/Documents/$SINK_SUBDIR" ]]; then
    cp -f "$CONTAINER/Documents/$SINK_SUBDIR/"*.txt "$FILES_DIR/" 2>/dev/null || true
    COUNT="$(find "$FILES_DIR" -name '*.txt' | wc -l | tr -d ' ')"
    ok "pulled $COUNT evidence file(s) -> $FILES_DIR"
  else
    note "no evidence container found (Documents/$SINK_SUBDIR)"
  fi
  xcrun simctl spawn "$UDID" log show --last 30m --predicate "eventMessage CONTAINS \"$LOG_NAME\"" \
    --style compact >"$OSLOG_RAW" 2>/dev/null || true
else
  # Physical device branch: pull over SSH/scp from the jailbroken sandbox.
  # (Same conventions as docs/device-access/ios/verify.md.) Needs a jailbroken
  # device with OpenSSH; the app's Documents container is mobile-owned.
  SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5)

  discover_device_ip() {
    if [[ -n "${DEVICE_IP:-}" ]]; then echo "$DEVICE_IP"; return; fi
    # Primary: match the device's Wi-Fi MAC in the Mac's ARP table. Requires
    # "Private Wi-Fi Address" to be OFF on the device (otherwise it rotates a
    # random MAC that won't match ideviceinfo's WiFiAddress).
    local mac ip
    mac="$(ideviceinfo -u "$UDID" -k WiFiAddress 2>/dev/null | tr -d '[:space:]')"
    if [[ -n "$mac" ]]; then
      # Populate ARP with a quick subnet ping, then match (macOS arp strips
      # leading zeros, so match loosely on the de-zeroed MAC too).
      local subnet
      subnet="$(ipconfig getifaddr en0 2>/dev/null | sed 's/\.[0-9]*$/./')" || true
      if [[ -n "$subnet" ]]; then
        for i in $(seq 1 254); do ping -c1 -W1 "${subnet}${i}" >/dev/null 2>&1 & done; wait
      fi
      ip="$(arp -a | awk -F'[()]' -v mac="$mac" '$0 ~ mac {print $2; exit}')"
      [[ -z "$ip" ]] && ip="$(arp -a | awk -F'[()]' -v mac="$(echo "$mac" | sed 's/0\([0-9a-f]\)/\1/g')" '$0 ~ mac {print $2; exit}')"
      if [[ -n "$ip" ]]; then echo "$ip"; return; fi
    fi
    # Fallback: sweep the subnet for a host answering with an SSH banner.
    local subnet2 found=""
    subnet2="$(ipconfig getifaddr en0 2>/dev/null | sed 's/\.[0-9]*$/./')" || true
    [[ -n "$subnet2" ]] || return 1
    for i in $(seq 1 254); do
      ( nc -G1 -w1 "${subnet2}${i}" 22 2>/dev/null | grep -q '^SSH-' && echo "${subnet2}${i}" ) &
    done > /tmp/dvma_ssh_scan.$$ 2>/dev/null
    wait
    found="$(head -1 /tmp/dvma_ssh_scan.$$ 2>/dev/null)"; rm -f /tmp/dvma_ssh_scan.$$
    [[ -n "$found" ]] && echo "$found"
  }

  IP="$(discover_device_ip || true)"
  if [[ -z "$IP" ]]; then
    bad "could not find the device on the LAN. Turn OFF the device's Private Wi-Fi Address (Settings → Wi-Fi → ⓘ), or pass DEVICE_IP=<ip>."
    docs "device-access/ios/verify/"
  else
    note "device IP: $IP (ssh $SSH_USER@$IP)"
    # Locate the app's data container by its bundle id, then scp the sink dir.
    REMOTE_C="$(ssh "${SSH_OPTS[@]}" "$SSH_USER@$IP" "
      for d in /var/mobile/Containers/Data/Application/*/; do
        if [ -d \"\$d/Documents/$SINK_SUBDIR\" ]; then echo \"\$d\"; break; fi
      done" 2>/dev/null | tr -d '\r')"
    if [[ -n "$REMOTE_C" ]]; then
      # The container path has no spaces; pass it unquoted. (Wrapping it in
      # single quotes makes modern scp/SFTP treat the quotes as part of the
      # filename and fail with "No such file or directory".)
      scp "${SSH_OPTS[@]}" -r "$SSH_USER@$IP:${REMOTE_C}Documents/$SINK_SUBDIR" "$FILES_DIR/tmp" >/dev/null 2>&1 || true
      find "$FILES_DIR/tmp" -name '*.txt' -exec mv -f {} "$FILES_DIR/" \; 2>/dev/null || true
      rm -rf "$FILES_DIR/tmp" 2>/dev/null || true
      COUNT="$(find "$FILES_DIR" -name '*.txt' | wc -l | tr -d ' ')"
      ok "pulled $COUNT evidence file(s) -> $FILES_DIR"
    else
      note "no evidence container found on device (Documents/$SINK_SUBDIR)"
    fi
    # Device os_log over SSH.
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$IP" \
      "log show --last 30m --predicate 'eventMessage CONTAINS \"$LOG_NAME\"' --style compact" \
      >"$OSLOG_RAW" 2>/dev/null || true
  fi
fi

# WDIO wrote per-module PNGs into automation/appium/artifacts/ (both targets).
if [[ -d "$APPIUM_DIR/artifacts" ]]; then
  mkdir -p "$ARTIFACTS/screenshots"
  cp -f "$APPIUM_DIR/artifacts/"*.png "$ARTIFACTS/screenshots/" 2>/dev/null || true
  SHOTS="$(find "$ARTIFACTS/screenshots" -name '*.png' | wc -l | tr -d ' ')"
  ok "copied $SHOTS screenshot(s) -> $ARTIFACTS/screenshots"
fi
if [[ -s "$OSLOG_RAW" ]]; then
  LINES="$(grep -c "$LOG_NAME" "$OSLOG_RAW" 2>/dev/null || echo 0)"
  ok "captured $LINES os_log evidence line(s) -> $OSLOG_RAW"
fi

say "Done"
note "artifacts: $ARTIFACTS"
exit "$WDIO_RC"
