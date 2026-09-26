#!/usr/bin/env bash
#
# DVMA first-run emulator bootstrap (Android).
#
# One command to go from a fresh checkout to the app running on an emulator.
# Built for newcomers who don't already have an AVD booted: it creates the AVD
# if it's missing, clears the stale lock/running-state that makes a
# just-crashed emulator refuse to start again, cold-boots it, waits for the
# device to finish booting, then runs the DVMA "full" flavor on it.
#
# The stale-lock cleanup is the important bit: if the emulator process is ever
# killed (window closed, machine sleep, an earlier crash), it leaves
# hardware-qemu.ini.lock / multiinstance.lock behind and the next launch dies a
# few seconds in - which looks like the app is broken when it isn't.
#
# FOR AUTHORIZED TRAINING USE ONLY. Use a disposable/test AVD.
#
# Usage (from repo root):
#   automation/scripts/bootstrap_emulator.sh
#
# Once it hands off to `flutter run`, this terminal owns the session: press
#   r  hot reload      R  hot restart (needed after new classes/fields)
#   q  quit
# in THIS window. (Hot reload is a keypress into the attached session; it can't
# be triggered from another terminal or by re-running the script.)
#
# Env overrides:
#   AVD           AVD name                 (default dvma_api34)
#   API           system-image API level   (default 34)
#   FLAVOR        dart-define-from-file     (default config/flavors/full.json)
#   SKIP_RUN      set to 1 to boot only, skip `flutter run`
#   STOP_DEVICE   set to 1 to shut the emulator down and exit (teardown only):
#                 `STOP_DEVICE=1 bootstrap_emulator.sh`
#   KILL_ON_EXIT  set to 1 to shut the emulator down when the run ends (Ctrl+C /
#                 q). Default leaves it booted so a re-run reuses it.
#   KEEP_EXISTING set to 1 to leave an already-attached `flutter run` alone
#                 (default: adopt the device by ending the orphaned session)
#   BOOT_TIMEOUT  seconds to wait for boot (default 240)
set -euo pipefail

AVD_NAME="${AVD:-dvma_api34}"
API="${API:-34}"
FLAVOR="${FLAVOR:-config/flavors/full.json}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-240}"

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

command -v flutter >/dev/null 2>&1 || die "flutter not found on PATH - install Flutter" "getting-started/installing-flutter/"

# SDK + tool resolution (portable; same technique as the appium harness).
resolve_sdk() {
  local sdk
  for sdk in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" \
             "$HOME/Library/Android/sdk" "$HOME/Android/Sdk" \
             "/opt/homebrew/share/android-commandlinetools" \
             "/usr/local/share/android-commandlinetools" \
             "/usr/lib/android-sdk"; do
    [[ -n "$sdk" && -d "$sdk" ]] && { echo "$sdk"; return; }
  done
  return 1
}
SDK="$(resolve_sdk || true)"
[[ -n "$SDK" ]] || die "Android SDK not found (set ANDROID_HOME or install the SDK)" "getting-started/prerequisites/#android"

find_tool() {
  # <name> <subdir...> - first executable match wins.
  local name="$1"; shift
  command -v "$name" >/dev/null 2>&1 && { command -v "$name"; return; }
  local d
  for d in "$@"; do
    [[ -x "$SDK/$d/$name" ]] && { echo "$SDK/$d/$name"; return; }
  done
  return 1
}
ADB="$(find_tool adb platform-tools || true)"
EMU="$(find_tool emulator emulator emulator/bin || true)"
AVDMANAGER="$(find_tool avdmanager cmdline-tools/latest/bin tools/bin || true)"
SDKMANAGER="$(find_tool sdkmanager cmdline-tools/latest/bin tools/bin || true)"
[[ -n "$ADB" ]] || die "adb not found under $SDK/platform-tools" "getting-started/prerequisites/#android"
[[ -n "$EMU" ]] || die "emulator not found under $SDK/emulator" "getting-started/prerequisites/#android"
note "sdk: $SDK"

# Shut the emulator down. `adb emu kill` asks the running instance to
# quit; fall back to killing the qemu process if the console is unresponsive.
stop_device() {
  local serial
  serial="$("$ADB" devices | awk 'NR>1 && $2=="device" && $1 ~ /^emulator-/ {print $1; exit}')"
  if [[ -n "$serial" ]]; then
    "$ADB" -s "$serial" emu kill >/dev/null 2>&1 || true
  fi
  pkill -f "qemu.*${AVD_NAME}" >/dev/null 2>&1 || true
  ok "emulator '$AVD_NAME' shut down"
}

# Standalone teardown: `STOP_DEVICE=1 bootstrap_emulator.sh` shuts the emulator
# down and exits without booting or running anything.
if [[ "${STOP_DEVICE:-}" == "1" && "${SKIP_RUN:-}" != "1" ]]; then
  say "Stopping emulator (STOP_DEVICE=1)"
  "$ADB" start-server >/dev/null 2>&1 || true
  stop_device
  exit 0
fi

# Create the AVD on first run if it doesn't exist yet.
if ! "$EMU" -list-avds 2>/dev/null | grep -qx "$AVD_NAME"; then
  say "Creating AVD '$AVD_NAME' (first run)"
  [[ -n "$AVDMANAGER" && -n "$SDKMANAGER" ]] \
    || die "avdmanager/sdkmanager not found - install the SDK command-line tools" "getting-started/prerequisites/#android"
  local_image="system-images;android-${API};google_apis;arm64-v8a"
  note "installing $local_image (once)"
  yes | "$SDKMANAGER" "emulator" "platform-tools" "$local_image" >/dev/null
  echo "no" | "$AVDMANAGER" create avd -n "$AVD_NAME" -k "$local_image" --device "pixel_7" --force
  ok "created $AVD_NAME"
fi

# Ensure the AVD has a hardware keyboard so the host (Mac) keyboard types - and,
# crucially, PASTES - into fields. With hw.keyboard=no Android forces the
# on-screen soft keyboard, which has no host-clipboard paste path, so a user
# can't paste their OpenRouter key into the BYOK dialog. Idempotent: rewrites an
# existing line or appends one. Read at boot, so callers must (re)boot after.
ensure_hw_keyboard() {
  local cfg="$HOME/.android/avd/${AVD_NAME}.avd/config.ini"
  [[ -f "$cfg" ]] || return 0
  if grep -q '^hw\.keyboard=' "$cfg"; then
    grep -q '^hw\.keyboard=yes$' "$cfg" && return 0
    # Rewrite in place without needing sed -i portability quirks.
    local tmp; tmp="$(mktemp)"
    sed 's/^hw\.keyboard=.*/hw.keyboard=yes/' "$cfg" >"$tmp" && mv "$tmp" "$cfg"
  else
    printf 'hw.keyboard=yes\n' >>"$cfg"
  fi
  note "hardware keyboard enabled (host keyboard + paste work)"
}
ensure_hw_keyboard

# Clear stale lock/running-state from any prior crashed instance. Without this,
# a fresh launch dies a few seconds in and looks like an app bug.
clear_stale_state() {
  local avd_dir="$HOME/.android/avd/${AVD_NAME}.avd"
  if [[ -d "$avd_dir" ]]; then
    rm -f "$avd_dir"/*.lock 2>/dev/null || true
  fi
  rm -rf "$HOME/Library/Caches/TemporaryItems/avd/running" 2>/dev/null || true
}

# If it's already booted, reuse it rather than starting a second instance.
"$ADB" start-server >/dev/null 2>&1 || true
if "$ADB" devices | awk 'NR>1 && $2=="device"{f=1} END{exit !f}'; then
  ok "an emulator/device is already connected - reusing it"
else
  say "Booting '$AVD_NAME' (first cold boot can take ~2 minutes)"
  clear_stale_state
  # -no-snapshot-load forces a clean cold boot so a corrupt saved snapshot can't
  # crash startup (the other failure mode newcomers hit).
  nohup "$EMU" -avd "$AVD_NAME" -no-snapshot-load >/tmp/dvma_emu.log 2>&1 &
  disown
  note "emulator log: /tmp/dvma_emu.log"

  "$ADB" wait-for-device
  waited=0
  until [[ "$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]]; do
    if ! pgrep -f "qemu.*${AVD_NAME}" >/dev/null 2>&1; then
      bad "emulator process exited during boot - last log lines:"
      tail -15 /tmp/dvma_emu.log 2>/dev/null || true
      die "emulator failed to boot (see /tmp/dvma_emu.log)" "getting-started/prerequisites/#android"
    fi
    (( waited += 3 ))
    if (( waited >= BOOT_TIMEOUT )); then
      die "timed out after ${BOOT_TIMEOUT}s waiting for boot (see /tmp/dvma_emu.log)" "getting-started/prerequisites/#android"
    fi
    sleep 3
  done
  ok "emulator booted"
fi

if [[ "${SKIP_RUN:-}" == "1" ]]; then
  ok "emulator ready (SKIP_RUN=1 set; not launching the app)"
  exit 0
fi

# Pin `flutter run` to the emulator we booted, so it doesn't prompt when other
# devices (Chrome, a plugged-in phone, an iPad) are also available.
TARGET_SERIAL="$("$ADB" devices | awk 'NR>1 && $2=="device" && $1 ~ /^emulator-/ {print $1; exit}')"
[[ -n "$TARGET_SERIAL" ]] || TARGET_SERIAL="$("$ADB" devices | awk 'NR>1 && $2=="device" {print $1; exit}')"

say "Running DVMA ($FLAVOR) on ${TARGET_SERIAL:-the connected device}"

# Guard against a leftover `flutter run` already attached to this device. If one
# exists (e.g. from a terminal you've since lost track of), a second session
# fights it for the device and, worse, the hot-reload keys (r/R) only work in
# whichever terminal owns the ATTACHED session - so you can end up staring at a
# logcat window pressing r with nothing happening. Adopt the session by killing
# the orphan so THIS terminal's `flutter run` owns it and r/R work here. Set
# KEEP_EXISTING=1 to leave any existing session alone instead.
if [[ "${KEEP_EXISTING:-}" != "1" ]]; then
  # Match a flutter_tools `run` bound to our device (or a device-less `run`).
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
  if [[ -n "$TARGET_SERIAL" ]]; then
    flutter run -d "$TARGET_SERIAL" --dart-define-from-file="$FLAVOR"
  else
    flutter run --dart-define-from-file="$FLAVOR"
  fi
}

# When KILL_ON_EXIT=1, shut the emulator down once the run ends (Ctrl+C, `q`, or
# a build failure). Default leaves it booted so re-running the script reuses it
# and skips the ~2-minute cold boot.
if [[ "${KILL_ON_EXIT:-}" == "1" ]]; then
  trap 'echo; stop_device' EXIT
fi

# First attempt. If the build trips over a half-written build cache (the
# "package identifier or launch activity not found" / "No application found for
# TargetPlatform" symptom a newcomer hits after an interrupted build), clean and
# retry once so the script recovers on its own instead of looking broken.
if run_flutter; then
  exit 0
fi

bad "first launch failed - cleaning the build cache and retrying once"
flutter clean >/dev/null 2>&1 || true
flutter pub get >/dev/null 2>&1 || true
if run_flutter; then
  exit 0
fi

# The clean rebuild also failed, so this isn't a stale cache - surface enough to
# diagnose (analyzer + emulator log) instead of dying silently.
bad "launch still failed after a clean rebuild - this is a real build/run error, not stale state"
note "running 'flutter analyze' to surface any code errors:"
flutter analyze 2>&1 | tail -20 || true
note "recent emulator log (/tmp/dvma_emu.log):"
tail -15 /tmp/dvma_emu.log 2>/dev/null || true
die "could not launch DVMA on the emulator (see analyzer output and /tmp/dvma_emu.log above)" "getting-started/prerequisites/#android"
