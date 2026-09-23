#!/usr/bin/env bash
# demo_broadcast_ipc.sh - end-to-end demo/verification for the broadcast-IPC
# cross-app modules. FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
#
# Drives DVMA (com.dvma) and the companion attacker (com.dvma.attacker) on a
# connected device to prove each broadcast vulnerability crosses a process
# boundary:
#
#   Receive-side (attacker SENDS -> DVMA's exported receiver applies):
#     - exported_broadcast_receiver_spoof   (spoofed LOCATION_UPDATE)
#     - dynamic_broadcast_receiver_exposure (forged APPLY_PROMO)
#
#   Send-side (DVMA emits -> attacker RECEIVES/reorders):
#     - implicit_intent_sensitive_data      (implicit SHARE_SESSION extras)
#     - ordered_broadcast_result_injection  (attacker rewrites ordered result)
#     - default_role_holder_confusion       (attacker receives role secret)
#
# Usage:
#   automation/scripts/demo_broadcast_ipc.sh          # build+install+run
#   SKIP_BUILD=1 automation/scripts/demo_broadcast_ipc.sh
set -uo pipefail

ADB=(adb)
PKG="com.dvma"
ATTACKER_PKG="com.dvma.attacker"
FLAVOR="config/flavors/full.json"
DVMA_APK="build/app/outputs/flutter-apk/app-debug.apk"
ATTACKER_DIR="companion/dvma-attacker"
ATTACKER_APK="$ATTACKER_DIR/app/build/outputs/apk/debug/app-debug.apk"

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

FAILED=0

_dump() { "${ADB[@]}" exec-out uiautomator dump /dev/tty 2>/dev/null \
            | sed 's/UI hierchary dumped to.*//'; }
tap_id() {
  local id="$1" xml cx cy bounds
  for _ in 1 2 3 4 5 6; do
    xml="$(_dump || true)"
    bounds="$(printf '%s' "$xml" \
      | grep -o "resource-id=\"$id\"[^>]*bounds=\"[^\"]*\"" \
      | grep -o 'bounds="[^"]*"' | head -1 \
      | grep -o '[0-9]\+' | paste -sd' ' -)"
    if [[ -n "$bounds" ]]; then
      cx=$(( ( $(echo "$bounds" | cut -d' ' -f1) + $(echo "$bounds" | cut -d' ' -f3) ) / 2 ))
      cy=$(( ( $(echo "$bounds" | cut -d' ' -f2) + $(echo "$bounds" | cut -d' ' -f4) ) / 2 ))
      "${ADB[@]}" shell input tap "$cx" "$cy"
      return 0
    fi
    sleep 1
  done
  return 1
}
has_id() { _dump | grep -q "resource-id=\"$1\""; }

# Ensure the attacker process is actually alive (Android may kill it between
# steps). Its runtime-registered receivers only exist while the process runs,
# and they're what win ordered-broadcast priority / receive delegated roles.
ensure_attacker() {
  local pid
  pid="$("${ADB[@]}" shell pidof "$ATTACKER_PKG" | tr -d '\r')"
  if [[ -z "$pid" ]]; then
    "${ADB[@]}" shell am start -n "$ATTACKER_PKG/.AttackerActivity" >/dev/null 2>&1
    sleep 3
    pid="$("${ADB[@]}" shell pidof "$ATTACKER_PKG" | tr -d '\r')"
  fi
  [[ -n "$pid" ]]
}

# close_shade : if the notification shade grabbed focus, close it. NEVER swipe
# down from the top edge here - that *opens* the shade. Use the statusbar
# command + BACK, which reliably collapses it.
close_shade() {
  for _ in 1 2 3; do
    "${ADB[@]}" shell dumpsys window 2>/dev/null | grep -qi "mCurrentFocus.*NotificationShade" || return 0
    "${ADB[@]}" shell cmd statusbar collapse >/dev/null 2>&1
    "${ADB[@]}" shell input keyevent KEYCODE_BACK >/dev/null 2>&1
    sleep 1
  done
}

# Bring DVMA to a clean, *searchable* home screen: close any open shade, go to
# the launcher, resume DVMA, then press BACK to pop any detail screen (resuming
# MainActivity alone just returns to the detail page that was last open).
dvma_home() {
  for _ in 1 2 3 4 5 6; do
    close_shade
    "${ADB[@]}" shell input keyevent KEYCODE_HOME >/dev/null 2>&1
    sleep 1
    "${ADB[@]}" shell am start -n "$PKG/.MainActivity" >/dev/null 2>&1
    sleep 1
    close_shade
    has_id "dvma_search_field" && return 0
    # A detail screen is up: pop back toward home.
    "${ADB[@]}" shell input keyevent KEYCODE_BACK >/dev/null 2>&1
    sleep 1
    has_id "dvma_search_field" && return 0
  done
  return 1
}

# open_module <query> <vuln_id> : reach home, clear any stale search text, type
# a fresh query, and open the module. The query uses %s for spaces (adb `input
# text` treats a literal space as an arg separator).
open_module() {
  local query="$1" vid="$2"
  dvma_home || { bad "couldn't reach DVMA home"; return 1; }
  tap_id "dvma_search_field" || return 1
  sleep 1
  # Clear stale text: jump to end and backspace generously so each search
  # starts fresh (the field retains text across activity relaunches).
  "${ADB[@]}" shell input keyevent KEYCODE_MOVE_END >/dev/null 2>&1
  for _ in $(seq 1 60); do "${ADB[@]}" shell input keyevent KEYCODE_DEL >/dev/null 2>&1; done
  "${ADB[@]}" shell input text "$query" >/dev/null 2>&1
  sleep 2
  tap_id "vuln_row_$vid" || return 1
  sleep 2
  has_id "demo_screen_$vid"
}

# assert_harvest <needle> <label> : attacker logcat contains a HARVESTED needle.
assert_harvest() {
  local needle="$1" label="$2"
  local hit
  hit="$("${ADB[@]}" logcat -d "DVMA-ATTACKER:W" "*:S" | grep -a "HARVESTED" | grep -a "$needle" | tail -1 || true)"
  if [[ -n "$hit" ]]; then
    ok "$label: attacker harvested across the boundary"
    printf '    \033[0;31m%s\033[0m\n' "${hit#*DVMA-ATTACKER: }"
  else
    bad "$label: no cross-app harvest observed"; FAILED=1
  fi
}

# assert_applied <needle> <label> : DVMA logcat shows an exported receiver applied it.
assert_applied() {
  local needle="$1" label="$2"
  local hit
  hit="$("${ADB[@]}" logcat -d "DVMA-EVIDENCE:W" "*:S" | grep -a "$needle" | tail -1 || true)"
  if [[ -n "$hit" ]]; then
    ok "$label: DVMA's exported receiver applied attacker input"
    printf '    \033[0;31m%s\033[0m\n' "${hit#*DVMA-EVIDENCE: }"
  else
    bad "$label: DVMA did not apply the attacker broadcast"; FAILED=1
  fi
}

# Preflight / build / install
say "Preflight: adb device"
"${ADB[@]}" get-state >/dev/null 2>&1 || { bad "no device via adb"; exit 1; }
note "device: $("${ADB[@]}" get-serialno)"

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  say "Building DVMA + attacker APKs"
  flutter build apk --debug --dart-define-from-file="$FLAVOR" >/dev/null && ok "built DVMA"
  ( cd "$ATTACKER_DIR" && ./gradlew -q :app:assembleDebug ) && ok "built attacker"
fi

say "Installing both apps (separate packages / UIDs / signing keys)"
"${ADB[@]}" install -r "$DVMA_APK" >/dev/null && ok "installed $PKG"
"${ADB[@]}" install -r "$ATTACKER_APK" >/dev/null && ok "installed $ATTACKER_PKG"
"${ADB[@]}" shell pm grant "$ATTACKER_PKG" android.permission.POST_NOTIFICATIONS 2>/dev/null || true

say "Starting the attacker's harvest service (registers broadcast receivers)"
"${ADB[@]}" shell am force-stop "$ATTACKER_PKG" 2>/dev/null || true
"${ADB[@]}" shell rm -f "/sdcard/Android/data/$ATTACKER_PKG/files/attacker_captures.txt" 2>/dev/null || true
ensure_attacker && ok "attacker service running (pid $("${ADB[@]}" shell pidof "$ATTACKER_PKG" | tr -d '\r'))" || bad "attacker did not start"

# Receive-side: attacker SENDS, DVMA's exported receiver applies
say "exported_broadcast_receiver_spoof - attacker spoofs a location broadcast"
"${ADB[@]}" shell am start -n "$PKG/.MainActivity" >/dev/null 2>&1; sleep 2
"${ADB[@]}" logcat -c
"${ADB[@]}" shell am force-stop "$ATTACKER_PKG" 2>/dev/null || true
"${ADB[@]}" shell am start -n "$ATTACKER_PKG/.AttackerActivity" --es send location >/dev/null 2>&1
sleep 3
assert_applied "applied location extras" "exported_broadcast_receiver_spoof"

say "dynamic_broadcast_receiver_exposure - attacker forges a promo broadcast"
"${ADB[@]}" shell am start -n "$PKG/.MainActivity" >/dev/null 2>&1; sleep 2
"${ADB[@]}" logcat -c
"${ADB[@]}" shell am force-stop "$ATTACKER_PKG" 2>/dev/null || true
"${ADB[@]}" shell am start -n "$ATTACKER_PKG/.AttackerActivity" --es send promo >/dev/null 2>&1
sleep 3
assert_applied "applied promo extras" "dynamic_broadcast_receiver_exposure"

# Restart the attacker's persistent service for the send-side receivers.
"${ADB[@]}" shell am force-stop "$ATTACKER_PKG" 2>/dev/null || true
"${ADB[@]}" shell am start -n "$ATTACKER_PKG/.AttackerActivity" >/dev/null 2>&1
sleep 3

# Send-side: DVMA emits, attacker RECEIVES/reorders
say "implicit_intent_sensitive_data - DVMA broadcasts sensitive extras implicitly"
ensure_attacker || { bad "attacker process not alive"; FAILED=1; }
"${ADB[@]}" logcat -c
if open_module "Implicit%sIntent" "implicit_intent_sensitive_data"; then
  tap_id "demo_action_broadcast_implicit" && sleep 3
  assert_harvest "session extras" "implicit_intent_sensitive_data"
else
  bad "implicit_intent_sensitive_data: couldn't open module"; FAILED=1
fi

say "ordered_broadcast_result_injection - attacker rewrites the ordered result"
ensure_attacker || { bad "attacker process not alive"; FAILED=1; }
"${ADB[@]}" logcat -c
if open_module "Ordered" "ordered_broadcast_result_injection"; then
  tap_id "demo_action_broadcast_entitlement_check" && sleep 3
  assert_harvest "rewrote ordered result" "ordered_broadcast_result_injection"
else
  bad "ordered_broadcast_result_injection: couldn't open module"; FAILED=1
fi

say "default_role_holder_confusion - attacker receives the delegated role secret"
ensure_attacker || { bad "attacker process not alive"; FAILED=1; }
"${ADB[@]}" logcat -c
if open_module "role" "default_role_holder_confusion"; then
  tap_id "demo_action_delegate_secret_to_default_role_holder" && sleep 3
  assert_harvest "role secret" "default_role_holder_confusion"
else
  bad "default_role_holder_confusion: couldn't open module"; FAILED=1
fi

# Summary
if [[ "$FAILED" == "0" ]]; then
  say "All broadcast-IPC modules verified across the process boundary."
else
  say "Some broadcast-IPC checks did not observe the cross-app effect (see above)."
fi
exit "$FAILED"
