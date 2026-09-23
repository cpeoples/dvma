#!/usr/bin/env bash
# demo_exported_components.sh - end-to-end demo/verification for the exported
# Android COMPONENT modules. FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
#
# Drives DVMA (com.dvma) and the companion attacker (com.dvma.attacker) on a
# connected device to prove each exported-component vulnerability crosses a
# real process/trust boundary. DVMA declares an Activity/Service/alias exported
# with NO caller check; the separately-signed, unprivileged attacker reaches it
# by explicit component name (an `am start`/`bind` from its own UID). DVMA
# records the effect in EvidenceStore, which the Dart side reads back over the
# dvma/component_ipc channel - the same read-back pattern the broadcast group
# uses.
#
# Modules covered (one dedicated exported component each):
#
#   Exported Activities (attacker SENDS an intent -> DVMA acts on its behalf):
#     - exported_android_components              (AdminActivity)
#     - exported_component_arbitrary_url_activity (UrlDispatchActivity)
#     - exported_component_state_manipulation     (StateControlActivity)
#     - confused_deputy_intent_validation         (DeputyActivity)
#     - intent_redirection                        (ProxyActivity -> InternalAdminActivity)
#     - intent_arg_injection_rce                  (LauncherActivity)
#     - activity_alias_exposure                   (AdminAlias -> ProtectedAdminActivity)
#     - cross_app_scripting                       (WebViewActivity)
#
#   Exported Service (attacker BINDS -> harvests the privileged reply):
#     - privileged_service_binding_exposure       (PrivilegedService)
#
#   Task-stack hijack (attacker reparents its Activity into DVMA's task):
#     - activity_task_stack_hijacking             (HijackActivity -> DVMA task)
#
# DEVICE-BEHAVIOR NOTE (baked in below): before each `--es start`/`--es bind`
# the script force-stops BOTH apps and re-cold-starts the attacker, so the extra
# is handled in a fresh onCreate and the launch counts as a foreground start.
# Otherwise Android's background-activity-launch limits silently drop it (and a
# stale DVMA activity left in the attacker's task would poison the next start).
# This mirrors the same freshness requirement the broadcast group has.
#
# Usage (run from the repo root; works on any connected device):
#   automation/scripts/demo_exported_components.sh          # build+install+run
#   SKIP_BUILD=1 automation/scripts/demo_exported_components.sh   # reuse APKs
#   SERIAL=<serial> automation/scripts/demo_exported_components.sh # pick a device
#
# adb is auto-located (PATH, then $ANDROID_HOME/$ANDROID_SDK_ROOT, then the
# default SDK install path); override with ADB=/path/to/adb if needed.
set -uo pipefail

PKG="${PKG:-com.dvma}"
ATTACKER_PKG="${ATTACKER_PKG:-com.dvma.attacker}"
FLAVOR="${FLAVOR:-config/flavors/full.json}"
DVMA_APK="build/app/outputs/flutter-apk/app-debug.apk"
ATTACKER_DIR="companion/dvma-attacker"
ATTACKER_APK="$ATTACKER_DIR/app/build/outputs/apk/debug/app-debug.apk"

# adb resolution (portable). Find adb without assuming it's on PATH or living
# in a machine-specific spot.
# Precedence: explicit $ADB override -> PATH -> $ANDROID_HOME/$ANDROID_SDK_ROOT
# -> the platform's default SDK install location. Works on any contributor's
# machine (macOS/Linux) without editing this script.
resolve_adb() {
  # 1) explicit override: ADB=/path/to/adb  (read as a scalar before we
  #    reassign ADB to a command array below)
  local override="${ADB:-}"
  if [[ -n "$override" && -x "$override" ]]; then echo "$override"; return; fi
  # 2) already on PATH
  if command -v adb >/dev/null 2>&1; then command -v adb; return; fi
  # 3) SDK env vars, then common default install locations
  local sdk cand
  for sdk in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" \
             "$HOME/Library/Android/sdk" "$HOME/Android/Sdk" \
             "/opt/homebrew/share/android-commandlinetools" \
             "/usr/local/share/android-commandlinetools" \
             "/usr/lib/android-sdk"; do
    [[ -n "$sdk" ]] || continue
    cand="$sdk/platform-tools/adb"
    if [[ -x "$cand" ]]; then echo "$cand"; return; fi
  done
  return 1
}

ADB_PATH="$(resolve_adb || true)"
if [[ -z "$ADB_PATH" ]]; then
  printf '\033[0;31m✗ adb not found.\033[0m Put it on PATH, or set one of:\n' >&2
  printf '    ADB=/path/to/adb   ANDROID_HOME=/path/to/sdk   ANDROID_SDK_ROOT=/path/to/sdk\n' >&2
  exit 1
fi

ADB=("$ADB_PATH")
# Target a specific device with SERIAL=<serial>; otherwise use the sole device.
if [[ -n "${SERIAL:-}" ]]; then ADB=("$ADB_PATH" -s "$SERIAL"); fi

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

FAILED=0

# Cross-app trigger helpers. The attacker's AttackerActivity reads
# `--es start <kind>` / `--es bind <kind>`
# and drives ComponentInvoker/ServiceBinderClient from its own UID.
#
# DEVICE-BEHAVIOR REQUIREMENT (observed on Android 12+ with modern BAL rules):
# the extra must be handled in a genuinely FRESH onCreate while the attacker is
# the resumed/foreground app - otherwise Android's background-activity-launch
# (BAL) limits silently drop the exported-component start it makes.
#
# The trap: if the attacker's task already exists (e.g. from a prior case) or
# another app was just brought foreground, `am start` reports "brought to the
# front" / "delivered to the top-most instance" and the extra is routed to
# onNewIntent on a NON-foreground instance - BAL then drops the launch. So we
# must (1) force-stop the attacker to kill its task, (2) press HOME so nothing
# else is the resumed top, then (3) do a SINGLE `am start` carrying the extra.
# That yields a cold onCreate with the attacker foreground. We do NOT pre-
# foreground DVMA (that would steal top); the exported-component start itself
# spins up DVMA's process, which hosts the EvidenceStore the effect lands in.
attacker_deliver() {  # <extra_key> <kind>   e.g. attacker_deliver start admin
  local key="$1" kind="$2"
  # Force-stop BOTH apps: killing only the attacker leaves DVMA's NoDisplay/
  # WebView activities (which the attacker launched into ITS task via
  # startActivityForResult) reparented in that task, polluting the next fresh
  # start so the extra routes to onNewIntent on the wrong top activity and BAL
  # drops the launch. Stopping DVMA too guarantees a clean attacker task.
  "${ADB[@]}" shell am force-stop "$PKG" >/dev/null 2>&1 || true
  "${ADB[@]}" shell am force-stop "$ATTACKER_PKG" >/dev/null 2>&1 || true
  "${ADB[@]}" shell input keyevent KEYCODE_HOME >/dev/null 2>&1
  sleep 1
  "${ADB[@]}" shell am start -n "$ATTACKER_PKG/.AttackerActivity" \
    --es "$key" "$kind" >/dev/null 2>&1
}

attacker_start() { attacker_deliver start "$1"; }
attacker_bind()  { attacker_deliver bind  "$1"; }

# assert_evidence <needle> <label> : DVMA's DVMA-EVIDENCE logcat shows an
# exported component acted on the attacker's request across the boundary.
assert_evidence() {
  local needle="$1" label="$2" hit
  hit="$("${ADB[@]}" logcat -d "DVMA-EVIDENCE:W" "*:S" | grep -a "$needle" | tail -1 || true)"
  if [[ -n "$hit" ]]; then
    ok "$label: DVMA's exported component acted for the external caller"
    printf '    \033[0;31m%s\033[0m\n' "${hit#*DVMA-EVIDENCE: }"
  else
    bad "$label: no cross-app effect observed in DVMA-EVIDENCE"; FAILED=1
  fi
}

# assert_harvest <needle> <label> : the attacker's own logcat shows it harvested
# something back across the boundary (service reply / task-hijack landing).
assert_harvest() {
  local needle="$1" label="$2" hit
  hit="$("${ADB[@]}" logcat -d "DVMA-ATTACKER:W" "*:S" | grep -a "$needle" | tail -1 || true)"
  if [[ -n "$hit" ]]; then
    ok "$label: attacker harvested across the boundary"
    printf '    \033[0;31m%s\033[0m\n' "${hit#*DVMA-ATTACKER: }"
  else
    bad "$label: no cross-app harvest observed"; FAILED=1
  fi
}

# assert_task_hijacked <label> : a task bearing DVMA's affinity now hosts the
# ATTACKER's activity - the StrandHogg reparent, observable in dumpsys. This is
# the faithful proof for the task-hijack module (more reliable than a logcat
# race between DVMA's target Activity and the attacker's reparented one).
assert_task_hijacked() {
  local label="$1" hit
  hit="$("${ADB[@]}" shell dumpsys activity activities 2>/dev/null \
        | grep -aiE "Task\{.*A=[0-9]+:$PKG\b" -A6 \
        | grep -ai "$ATTACKER_PKG/.HijackActivity" | head -1 || true)"
  if [[ -n "$hit" ]]; then
    ok "$label: attacker activity reparented into a task with DVMA's affinity"
    printf '    \033[0;31m%s\033[0m\n' "$(echo "$hit" | sed 's/^[[:space:]]*//')"
  else
    bad "$label: no attacker activity found in a DVMA-affinity task"; FAILED=1
  fi
}

# run_activity_case <kind> <needle> <label> : fresh-start the attacker with
# `--es start <kind>` and assert DVMA recorded the expected effect.
run_activity_case() {
  local kind="$1" needle="$2" label="$3"
  say "$label - attacker starts DVMA's exported component (--es start $kind)"
  "${ADB[@]}" logcat -c
  attacker_start "$kind"
  sleep 3
  assert_evidence "$needle" "$label"
}

# Preflight / build / install
say "Preflight: adb device"
note "adb: $ADB_PATH"
# Count attached devices (state == "device"). With no SERIAL and multiple
# devices, adb can't pick one - ask the caller to disambiguate rather than
# acting on an arbitrary device.
DEVICE_COUNT="$("${ADB[@]}" devices | awk 'NR>1 && $2=="device"' | wc -l | tr -d ' ')"
if [[ -z "${SERIAL:-}" && "${DEVICE_COUNT:-0}" -gt 1 ]]; then
  bad "multiple devices attached; pick one with SERIAL=<serial> (see 'adb devices')"
  "${ADB[@]}" devices | awk 'NR>1 && $2=="device"{print "    "$1}'
  exit 1
fi
"${ADB[@]}" get-state >/dev/null 2>&1 || { bad "no device via adb (check 'adb devices')"; exit 1; }
note "device: $("${ADB[@]}" get-serialno)"

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  say "Building DVMA + attacker APKs"
  flutter build apk --debug --dart-define-from-file="$FLAVOR" >/dev/null && ok "built DVMA"
  ( cd "$ATTACKER_DIR" && ./gradlew -q :app:assembleDebug ) && ok "built attacker"
else
  note "SKIP_BUILD=1 - using existing APKs"
fi

say "Installing both apps (separate packages / UIDs / signing keys)"
"${ADB[@]}" install -r "$DVMA_APK" >/dev/null && ok "installed $PKG (victim)"
"${ADB[@]}" install -r "$ATTACKER_APK" >/dev/null && ok "installed $ATTACKER_PKG (attacker)"
"${ADB[@]}" shell pm grant "$ATTACKER_PKG" android.permission.POST_NOTIFICATIONS 2>/dev/null || true
"${ADB[@]}" shell rm -f "/sdcard/Android/data/$ATTACKER_PKG/files/attacker_captures.txt" 2>/dev/null || true

# Exported Activities: attacker SENDS an intent, DVMA acts on its behalfrun_activity_case admin \
  "admin panel opened by $ATTACKER_PKG" \
  "exported_android_components"

run_activity_case url \
  "opened target=" \
  "exported_component_arbitrary_url_activity"

run_activity_case state \
  "cancelled notification id=" \
  "exported_component_state_manipulation"

run_activity_case deputy \
  "wrote secure setting" \
  "confused_deputy_intent_validation"

run_activity_case redirect \
  "internal-only InternalAdminActivity reached via redirection" \
  "intent_redirection"

run_activity_case arg \
  "dumped app secrets" \
  "intent_arg_injection_rce"

run_activity_case alias \
  "protected target reached via exported alias" \
  "activity_alias_exposure"

run_activity_case xss \
  "loaded url=" \
  "cross_app_scripting"

# Exported Service: attacker BINDS, harvests the privileged reply
say "privileged_service_binding_exposure - attacker binds DVMA's exported service (--es bind service)"
"${ADB[@]}" logcat -c
attacker_bind service
sleep 3
# Two-sided proof: DVMA served the secret, and the attacker harvested it.
assert_evidence "readSecret served to bound client" "privileged_service_binding_exposure (DVMA served)"
assert_harvest  "HARVESTED service secret"          "privileged_service_binding_exposure (attacker harvested)"

# Task-stack hijack: attacker reparents its Activity into DVMA's task
say "activity_task_stack_hijacking - attacker reparents into DVMA's task (--es start hijack)"
"${ADB[@]}" logcat -c
attacker_start hijack
sleep 3
# The faithful proof is the task placement: the attacker's activity lands in a
# task bearing DVMA's affinity (a phishing overlay that looks like DVMA).
assert_harvest "HIJACK attacker activity launched" "activity_task_stack_hijacking (attacker launched)"
assert_task_hijacked "activity_task_stack_hijacking (task placement)"
# DVMA's affinity-bearing target also starts, but the attacker's reparented
# activity preempts it immediately, so its DVMA-EVIDENCE line is best-effort
# (a benign race) - report it if present, but it does not gate the result.
dvma_hit="$("${ADB[@]}" logcat -d "DVMA-EVIDENCE:W" "*:S" | grep -a "HijackTargetActivity started with default taskAffinity" | tail -1 || true)"
[[ -n "$dvma_hit" ]] && note "DVMA target also ran: ${dvma_hit#*DVMA-EVIDENCE: }"

# Summary
if [[ "$FAILED" == "0" ]]; then
  say "All exported-component modules verified across the process boundary."
  exit 0
else
  say "Some exported-component checks did not observe the cross-app effect (see above)."
  exit 1
fi
