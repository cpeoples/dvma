#!/usr/bin/env bash
#
# DVMA - cross_app_otp_credential_leak END-TO-END DEMO (Android).
#
# FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
#
# This single script demonstrates a cross-app credential leak the way a
# researcher would, with ZERO manual taps. It:
#
#   1. installs DVMA + the standalone com.dvma.attacker companion app,
#   2. starts the attacker's foreground service (persistent broadcast receiver),
#   3. drives DVMA to the "Cross-App OTP / Credential Leak" module by its stable
#      Semantics ids (not screen coordinates), so it works on any device,
#   4. taps "Broadcast OTP (unprotected)" -> DVMA fires an Android broadcast,
#   5. shows the attacker HARVESTING the OTP + auth deep link (logcat + file),
#   6. taps "Broadcast OTP (permission-scoped)" -> shows the attacker gets
#      NOTHING (delivery gated by a signature-level permission = the fix).
#
# What makes the leak "real": the attacker is a SEPARATE app (its own package,
# UID and signing key, requesting no special permissions). It can only see what
# a vulnerable DVMA genuinely leaks across the Android process/trust boundary -
# a single app cannot demonstrate this against itself.
#
# The moving pieces (so you know exactly what runs):
#
#   DVMA (victim)                     com.dvma.attacker (attacker)
#   Dart screen  -- MethodChannel --> (n/a)
#     otp_broadcast_bridge.dart
#   MainActivity.kt                    OtpHarvestService (foreground)
#     context.sendBroadcast(          registers OtpLeakReceiver at runtime
#        OTP_ISSUED, extras)   -------> onReceive() logs + writes file
#     (secure path adds a               (Android drops the secure broadcast:
#      signature-level permission)       attacker isn't signed with DVMA's key)
#
# Usage:
#   automation/scripts/demo_cross_app_otp.sh            # full demo
#   SERIAL=<serial> automation/scripts/demo_cross_app_otp.sh
#   SKIP_BUILD=1 automation/scripts/demo_cross_app_otp.sh  # reuse built APKs
#
# Env overrides:
#   PKG           DVMA app id           (default com.dvma)
#   ATTACKER_PKG  attacker app id       (default com.dvma.attacker)
#   SERIAL        adb -s target         (default: first device)
#   FLAVOR        dart-define flavor    (default config/flavors/full.json)
#   SKIP_BUILD    set to 1 to skip building the two APKs
set -euo pipefail

PKG="${PKG:-com.dvma}"
ATTACKER_PKG="${ATTACKER_PKG:-com.dvma.attacker}"
ATTACKER_DIR="companion/dvma-attacker"
FLAVOR="${FLAVOR:-config/flavors/full.json}"
DVMA_APK="build/app/outputs/flutter-apk/app-debug.apk"
ATTACKER_APK="$ATTACKER_DIR/app/build/outputs/apk/debug/app-debug.apk"
ACTION="com.dvma.action.OTP_ISSUED"

ADB=(adb)
if [[ -n "${SERIAL:-}" ]]; then ADB=(adb -s "$SERIAL"); fi

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

# Drive the Flutter UI by stable Semantics resource-id, not coordinates. The app
# wraps every automatable widget with testId(id, ...) (lib/core/
# test_ids.dart), so the id shows up as an Android resource-id. We dump the
# view hierarchy, read the element's bounds, and tap its center.
_dump() { "${ADB[@]}" exec-out uiautomator dump /dev/tty 2>/dev/null \
            | sed 's/UI hierchary dumped to.*//'; }

# tap_id <resource-id> : tap the center of the element with that resource-id.
tap_id() {
  local id="$1" xml cx cy bounds
  for _ in 1 2 3 4 5 6; do
    xml="$(_dump || true)"
    bounds="$(printf '%s' "$xml" \
      | grep -o "resource-id=\"$id\"[^>]*bounds=\"[^\"]*\"" \
      | grep -o 'bounds="[^"]*"' | head -1 \
      | grep -o '[0-9]\+' | paste -sd' ' -)"
    if [[ -n "$bounds" ]]; then
      # bounds = "x1 y1 x2 y2"
      cx=$(( ( $(echo "$bounds" | cut -d' ' -f1) + $(echo "$bounds" | cut -d' ' -f3) ) / 2 ))
      cy=$(( ( $(echo "$bounds" | cut -d' ' -f2) + $(echo "$bounds" | cut -d' ' -f4) ) / 2 ))
      "${ADB[@]}" shell input tap "$cx" "$cy"
      return 0
    fi
    sleep 1
  done
  return 1
}

# has_id <resource-id> : true if the element is currently on screen.
has_id() { _dump | grep -q "resource-id=\"$1\""; }

# Preflight
say "Preflight: adb device"
"${ADB[@]}" get-state >/dev/null 2>&1 || { bad "no device via adb (check 'adb devices')"; exit 1; }
note "device: $("${ADB[@]}" get-serialno)"

# Build
if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  say "Building DVMA debug APK ($FLAVOR)"
  flutter build apk --debug --dart-define-from-file="$FLAVOR" >/dev/null
  ok "built $DVMA_APK"
  say "Building companion attacker APK"
  ( cd "$ATTACKER_DIR" && ./gradlew -q :app:assembleDebug )
  ok "built $ATTACKER_APK"
else
  note "SKIP_BUILD=1 - using existing APKs"
fi

# Install
say "Installing both apps (separate packages / UIDs / signing keys)"
"${ADB[@]}" install -r "$DVMA_APK" >/dev/null && ok "installed $PKG (victim)"
"${ADB[@]}" install -r "$ATTACKER_APK" >/dev/null && ok "installed $ATTACKER_PKG (attacker)"

# Start the attacker's persistent receiver
say "Starting the attacker's harvest service"
note "Android 8+ won't deliver implicit broadcasts to manifest receivers, so a"
note "real co-resident attacker keeps a RUNTIME receiver alive in a foreground"
note "service - exactly what OtpHarvestService does."
"${ADB[@]}" shell pm grant "$ATTACKER_PKG" android.permission.POST_NOTIFICATIONS 2>/dev/null || true
"${ADB[@]}" shell rm -f "/sdcard/Android/data/$ATTACKER_PKG/files/attacker_captures.txt" 2>/dev/null || true
"${ADB[@]}" shell am start -n "$ATTACKER_PKG/.AttackerActivity" >/dev/null
sleep 3
ok "attacker foreground service running, receiver registered for $ACTION"

# Start capturing the attacker's logcatATTACKER_LOG="$(mktemp -t dvma_attacker.XXXXXX)"
"${ADB[@]}" logcat -c || true
"${ADB[@]}" logcat -s DVMA-ATTACKER:* > "$ATTACKER_LOG" 2>/dev/null &
LOGCAT_PID=$!
trap 'kill $LOGCAT_PID 2>/dev/null || true; rm -f "$ATTACKER_LOG"' EXIT

# Drive DVMA to the module
say "Launching DVMA and navigating to the module (by Semantics id)"
"${ADB[@]}" shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 3
# Open the row directly if visible; otherwise search for it.
if ! has_id "vuln_row_cross_app_otp_credential_leak"; then
  note "searching for the module"
  tap_id "dvma_search_field" || true
  sleep 1
  "${ADB[@]}" shell input text "cross-app" 2>/dev/null || true
  sleep 2
fi
tap_id "vuln_row_cross_app_otp_credential_leak" \
  || { bad "could not find the module row"; exit 1; }
sleep 2
has_id "demo_action_broadcast_otp_unprotected" \
  && ok "on the Cross-App OTP module" \
  || { bad "module screen didn't open"; exit 1; }

# VULN PATH: unprotected broadcast
say "VULN: tapping 'Broadcast OTP (unprotected)' - DVMA fires a broadcast"
tap_id "demo_action_broadcast_otp_unprotected" || { bad "button not found"; exit 1; }
sleep 3
HARVEST="$(grep -a 'HARVESTED' "$ATTACKER_LOG" | tail -1 || true)"
if [[ -n "$HARVEST" ]]; then
  ok "attacker HARVESTED the secret across the process boundary:"
  printf '    \033[0;31m%s\033[0m\n' "${HARVEST#*DVMA-ATTACKER: }"
else
  bad "no harvest captured (is the attacker service still running?)"
fi

# SECURE PATH: permission-scoped broadcast
say "FIX: tapping 'Broadcast OTP (permission-scoped)' - signature permission gate"
"${ADB[@]}" shell rm -f "/sdcard/Android/data/$ATTACKER_PKG/files/attacker_captures.txt" 2>/dev/null || true
BEFORE="$(grep -ac 'HARVESTED' "$ATTACKER_LOG" || true)"
tap_id "demo_action_broadcast_otp_permission_scoped" || { bad "button not found"; exit 1; }
sleep 3
AFTER="$(grep -ac 'HARVESTED' "$ATTACKER_LOG" || true)"
if [[ "$AFTER" == "$BEFORE" ]]; then
  ok "attacker received NOTHING - Android dropped the delivery (not signed with"
  ok "DVMA's key, so it can't hold com.dvma.permission.RECEIVE_OTP)"
else
  bad "attacker unexpectedly harvested on the secure path - investigate"
fi

# Evidence summary
say "Evidence (also visible in DVMA's on-screen panels)"
note "logcat, tag DVMA-ATTACKER:"
grep -a 'HARVESTED' "$ATTACKER_LOG" | sed 's/^/    /' || note "    (none)"
CAPFILE="/sdcard/Android/data/$ATTACKER_PKG/files/attacker_captures.txt"
note "attacker's pullable capture file ($CAPFILE):"
"${ADB[@]}" shell cat "$CAPFILE" 2>/dev/null | sed 's/^/    /' || note "    (empty on secure path - as expected)"

say "Done."
note "Reproduce inside the app: open 'Cross-App OTP / Credential Leak' and tap the"
note "two buttons while running:  adb logcat -s DVMA-ATTACKER:*"
note "Full multi-module capture with a report:  ATTACKER=1 automation/scripts/capture_run.sh"
