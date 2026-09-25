#!/usr/bin/env bash
#
# DVMA first-run Simulator bootstrap (iOS).
#
# The iOS analogue of bootstrap_emulator.sh: one command to go from a fresh
# checkout to the app running on an iOS Simulator. Built for newcomers who don't
# already have a Simulator booted: it resolves (or boots) a Simulator, waits for
# it to finish booting, then runs the DVMA "full" flavor on it.
#
# Like the Android script it is self-healing. The equivalent iOS failure a
# newcomer hits after an interrupted build is a half-written build cache or a
# CocoaPods pod install that never completed, which shows up as
# "Could not build the ... application for the simulator" or a missing/partial
# Runner.app. On the first failure the script cleans the Flutter build cache,
# reinstalls pods, and retries once before surfacing a real error.
#
# FOR AUTHORIZED TRAINING USE ONLY. Use a disposable/test Simulator.
#
# Usage (from repo root):
#   automation/scripts/bootstrap_simulator.sh
#
# Once it hands off to `flutter run`, this terminal owns the session: press
#   r  hot reload      R  hot restart (needed after new classes/fields)
#   q  quit
# in THIS window.
#
# Env overrides:
#   DEVICE_NAME   simulator to boot if none booted (default "iPhone 17")
#   UDID          target simulator udid            (default: booted, else by name)
#   FLAVOR        dart-define-from-file            (default config/flavors/full.json)
#   SKIP_RUN      set to 1 to boot only, skip `flutter run`
#   KEEP_EXISTING set to 1 to leave an already-attached `flutter run` alone
#   BUNDLE_ID     app bundle id for the paste-policy pre-allow (default com.dvma)
#   BOOT_TIMEOUT  seconds to wait for boot         (default 240)
set -euo pipefail

DEVICE_NAME="${DEVICE_NAME:-iPhone 17}"
FLAVOR="${FLAVOR:-config/flavors/full.json}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-240}"

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

command -v flutter >/dev/null 2>&1 || die "flutter not found on PATH - install Flutter" "getting-started/installing-flutter/"
command -v xcrun   >/dev/null 2>&1 || die "xcrun not found - install the full Xcode app (not just Command Line Tools)" "getting-started/prerequisites/#host-toolchain"

# Resolve a target Simulator UDID: an already-booted one wins, else the newest
# available device matching DEVICE_NAME. Mirrors appium_run_ios.sh.
resolve_udid() {
  if [[ -n "${UDID:-}" ]]; then echo "$UDID"; return; fi
  local booted
  booted="$(xcrun simctl list devices booted -j 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin).get("devices",{});
print("\n".join(x["udid"] for v in d.values() for x in v if x.get("state")=="Booted"))' \
    | head -1)"
  if [[ -n "$booted" ]]; then echo "$booted"; return; fi
  xcrun simctl list devices available -j 2>/dev/null \
    | DEVICE_NAME="$DEVICE_NAME" python3 -c 'import json,sys,os; d=json.load(sys.stdin).get("devices",{}); name=os.environ["DEVICE_NAME"];
cands=[x["udid"] for v in d.values() for x in v if x.get("isAvailable") and x["name"]==name];
print(cands[0] if cands else "")' | head -1
}

device_state() {
  xcrun simctl list devices -j 2>/dev/null | UDID="$1" python3 -c 'import json,sys,os;u=os.environ["UDID"];d=json.load(sys.stdin).get("devices",{});
print(next((x["state"] for v in d.values() for x in v if x["udid"]==u), "Unknown"))' 2>/dev/null || echo Unknown
}

say "Resolving Simulator"
UDID="$(resolve_udid || true)"
if [[ -z "$UDID" ]]; then
  bad "no Simulator matched '$DEVICE_NAME' and none is booted"
  note "list what you have with: xcrun simctl list devices available"
  note "then re-run with DEVICE_NAME='iPhone 15' (or set UDID=<udid>)"
  die "no usable Simulator found" "getting-started/prerequisites/#host-toolchain"
fi
note "simulator udid: $UDID"

# Connect the hardware (Mac) keyboard so you can TYPE and, crucially, PASTE
# (Cmd-V) into fields - e.g. the BYOK dialog where you paste an OpenRouter key.
# (Mirrors the Android hw.keyboard=yes fix; a *disconnected* hardware keyboard
# forces the on-screen software keyboard, which has no Mac-clipboard paste
# path.) The catch: the iOS Simulator stores this BOTH globally AND per-device
# under DevicePreferences:<UDID>, and the per-device value WINS - so setting
# only the global key silently does nothing when a device already has its own.
# We set both. Simulator.app rewrites this plist on exit and reads it at launch,
# so we must write while it's NOT running and before booting.
ensure_hw_keyboard() {
  local plist="$HOME/Library/Preferences/com.apple.iphonesimulator.plist"
  # Quit Simulator so our edit isn't clobbered when it exits, then let it
  # relaunch below with the pref applied.
  if pgrep -x Simulator >/dev/null 2>&1; then
    osascript -e 'quit app "Simulator"' >/dev/null 2>&1 || true
    sleep 2
    pkill -x Simulator >/dev/null 2>&1 || true
    sleep 1
  fi
  # Global default (covers devices without a per-device override).
  defaults write com.apple.iphonesimulator ConnectHardwareKeyboard -bool true >/dev/null 2>&1 || true
  # Sync the Mac clipboard into the Simulator so Cmd-V pastes the host
  # clipboard (e.g. the copied OpenRouter key). Separate from the keyboard
  # setting - with this off, Cmd-V does nothing even with the HW keyboard on.
  defaults write com.apple.iphonesimulator PasteboardAutomaticSync -bool true >/dev/null 2>&1 || true
  # Per-device key (the one that actually wins). Set, else Add if absent.
  /usr/libexec/PlistBuddy -c "Set :DevicePreferences:${UDID}:ConnectHardwareKeyboard true" "$plist" >/dev/null 2>&1 \
    || /usr/libexec/PlistBuddy -c "Add :DevicePreferences:${UDID}:ConnectHardwareKeyboard bool true" "$plist" >/dev/null 2>&1 \
    || true
  note "hardware keyboard connected + clipboard sync on (host keyboard + Cmd-V paste work)"
}
ensure_hw_keyboard

# Boot it if it isn't already, then wait for boot to complete.
if [[ "$(device_state "$UDID")" != "Booted" ]]; then
  say "Booting Simulator (first cold boot can take a minute)"
  xcrun simctl boot "$UDID" 2>/dev/null || true
  # Bring the Simulator.app window up so it's usable for manual driving.
  open -a Simulator --args -CurrentDeviceUDID "$UDID" 2>/dev/null || open -a Simulator 2>/dev/null || true
  waited=0
  until [[ "$(device_state "$UDID")" == "Booted" ]]; do
    (( waited += 3 ))
    if (( waited >= BOOT_TIMEOUT )); then
      die "timed out after ${BOOT_TIMEOUT}s waiting for Simulator $UDID to boot" "getting-started/prerequisites/#host-toolchain"
    fi
    sleep 3
  done
  # simctl bootstatus blocks until the system is fully up (past the boot state).
  xcrun simctl bootstatus "$UDID" -b >/dev/null 2>&1 || true
  ok "simulator booted: $UDID"
else
  open -a Simulator --args -CurrentDeviceUDID "$UDID" 2>/dev/null || open -a Simulator 2>/dev/null || true
  ok "simulator already booted - reusing it: $UDID"
fi

if [[ "${SKIP_RUN:-}" == "1" ]]; then
  ok "simulator ready (SKIP_RUN=1 set; not launching the app)"
  exit 0
fi

# Pre-allow "Paste from Other Apps" for DVMA so the recurring iOS paste-
# permission prompt ("would like to paste from CoreSimulatorBridge") doesn't
# interrupt pasting the OpenRouter key. This is the app's per-app UIPasteboard
# cross-app policy (Settings > <app> > Paste from Other Apps > Allow); it only
# applies once the app is INSTALLED, so on a truly fresh checkout the very
# first launch may still prompt once (harmless - tap Allow), and every launch
# after is clean. Best-effort: never fail the run over it. Override the bundle
# id with BUNDLE_ID=... if you build a renamed flavor.
BUNDLE_ID="${BUNDLE_ID:-com.dvma}"
xcrun simctl spawn "$UDID" defaults write "$BUNDLE_ID" UIPasteboardAutomaticPasteEnabled -int 1 >/dev/null 2>&1 || true

# Pin `flutter run` to this Simulator so it doesn't prompt when other devices
# (Chrome, an Android emulator, a plugged-in phone) are also available.
say "Running DVMA ($FLAVOR) on simulator $UDID"

# Adopt the device if a stray `flutter run` is already attached (so THIS
# terminal owns the session and hot reload r / restart R work here). Set
# KEEP_EXISTING=1 to leave an existing session alone.
if [[ "${KEEP_EXISTING:-}" != "1" ]]; then
  existing_pids="$(pgrep -f "flutter_tools.snapshot run" 2>/dev/null || true)"
  if [[ -n "$existing_pids" ]]; then
    bad "found an existing 'flutter run' session (pid: $(echo "$existing_pids" | tr '\n' ' '))"
    note "ending it so THIS terminal owns the session (hot reload r / restart R work here)"
    note "set KEEP_EXISTING=1 to leave it running instead"
    # shellcheck disable=SC2086
    kill $existing_pids 2>/dev/null || true
    sleep 2
    # shellcheck disable=SC2086
    kill -9 $existing_pids 2>/dev/null || true
  fi
fi

run_flutter() {
  flutter run -d "$UDID" --dart-define-from-file="$FLAVOR"
}

# First attempt. On the first failure, recover from the two iOS-specific
# stale-state causes a newcomer hits: a half-written Flutter build cache and an
# out-of-sync CocoaPods install. Clean, reinstall pods, and retry once.
if run_flutter; then
  exit 0
fi

bad "first launch failed - cleaning the build cache + reinstalling pods, then retrying once"
flutter clean >/dev/null 2>&1 || true
flutter pub get >/dev/null 2>&1 || true
if [[ -d ios ]] && command -v pod >/dev/null 2>&1; then
  ( cd ios && pod install --repo-update >/dev/null 2>&1 ) || true
fi
if run_flutter; then
  exit 0
fi

# The clean rebuild also failed, so this isn't stale state - surface enough to
# diagnose (analyzer output) instead of dying silently.
bad "launch still failed after a clean rebuild - this is a real build/run error, not stale state"
note "running 'flutter analyze' to surface any code errors:"
flutter analyze 2>&1 | tail -20 || true
note "if the error mentions signing or provisioning, open ios/Runner.xcworkspace in Xcode once to let it provision."
die "could not launch DVMA on the Simulator" "getting-started/prerequisites/#host-toolchain"
