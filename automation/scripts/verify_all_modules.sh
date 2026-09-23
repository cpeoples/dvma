#!/usr/bin/env bash
# verify_all_modules.sh - on-device verification that every DVMA module is real.
# FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
#
# ANDROID-ONLY by construction (adb + UiAutomator). It walks every
# Android-applicable module from automation/vuln_manifest.json (shared + the
# `[android]` platform set - iOS-only modules are skipped, since they don't
# surface on Android). There is no iOS counterpart script: the iOS walk is the
# native XCUITest `RunnerUITests` suite, and iOS artifact verification is manual
# (device backup / jailbreak SSH - see the top-level README). It navigates to
# the module BY SEARCH (type the id into dvma_search_field, tap the single
# result row - deterministic, no scrolling, never touches screen edges / the
# app switcher), taps every demo_action_* button to trigger the vulnerable path,
# then asserts an evidence_* panel appears (every module renders an EvidencePanel,
# so a populated panel is on-device proof the vulnerable code path ran).
#
# Output: PASS (evidence panel present) / NO-EVIDENCE / NAV-FAIL per module, and
# a written summary at automation/artifacts/verify_all_modules.txt.
#
# Usage (from repo root):
#   automation/scripts/verify_all_modules.sh
#   SERIAL=<serial> automation/scripts/verify_all_modules.sh   # pick a device
#   ONLY=clipboard_leakage,insecure_backups automation/scripts/verify_all_modules.sh
#
# adb is auto-located (PATH -> $ANDROID_HOME/$ANDROID_SDK_ROOT -> default SDK).
set -uo pipefail

PKG="${PKG:-com.dvma}"
MANIFEST="${MANIFEST:-automation/vuln_manifest.json}"
TEST_IDS="${TEST_IDS:-lib/core/test_ids.dart}"
ARTIFACTS="${ARTIFACTS:-automation/artifacts}"
SUMMARY="$ARTIFACTS/verify_all_modules.txt"

# On-device pullable evidence dir written by DvmaEvidence.record() - see
# lib/core/evidence_sink.dart (external files dir + /dvma-artifacts). Modules
# that navigate away (launch an Activity/intent) or finish asynchronously may
# not have a visible evidence_* panel when we poll, but they DO drop/append
# <vulnId>.txt here - so a grown artifact file is equally valid on-device proof.
DEVICE_ARTIFACT_DIR="${DEVICE_ARTIFACT_DIR:-/storage/emulated/0/Android/data/$PKG/files/dvma-artifacts}"

# Stable id prefixes - parsed from the SINGLE SOURCE OF TRUTH# lib/core/test_ids.dart defines every id. We derive the prefixes from it at
# runtime so this script never drifts if they change. Each below is extracted
# from its String constant / builder in that file; if parsing fails we stop
# rather than silently use a wrong (hardcoded) guess.
id_const()  { grep -oE "$1 = '[^']+'" "$TEST_IDS" | grep -oE "'[^']+'" | tr -d "'" | head -1; }
id_prefix() { # extract the literal prefix from a builder like 'vuln_row_$vulnId'
  grep -oE "$1\(String [A-Za-z]+\) => '[^\$']+" "$TEST_IDS" | grep -oE "'[^\$']+" | tr -d "'" | head -1
}

SEARCH_FIELD="$(id_const searchField)"
DISCLAIMER="$(id_const disclaimerBanner)"
ROW_PREFIX="$(id_prefix vulnRow)"
SCREEN_PREFIX="$(id_prefix demoScreen)"
ACTION_PREFIX="$(id_prefix demoAction)"
EVIDENCE_PREFIX="$(id_prefix evidence)"
for v in SEARCH_FIELD:$SEARCH_FIELD DISCLAIMER:$DISCLAIMER ROW_PREFIX:$ROW_PREFIX \
         SCREEN_PREFIX:$SCREEN_PREFIX ACTION_PREFIX:$ACTION_PREFIX EVIDENCE_PREFIX:$EVIDENCE_PREFIX; do
  [[ -n "${v#*:}" ]] || { echo "could not parse ${v%%:*} from $TEST_IDS"; exit 1; }
done

# adb resolution (portable)
resolve_adb() {
  local override="${ADB:-}"
  if [[ -n "$override" && -x "$override" ]]; then echo "$override"; return; fi
  if command -v adb >/dev/null 2>&1; then command -v adb; return; fi
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
[[ -n "$ADB_PATH" ]] || { echo "adb not found (set ADB=, ANDROID_HOME, or PATH)"; exit 1; }
ADB=("$ADB_PATH")
if [[ -n "${SERIAL:-}" ]]; then ADB=("$ADB_PATH" -s "$SERIAL"); fi

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

# UI helpers (same technique as the working demo_*.sh)
_dump() { "${ADB[@]}" exec-out uiautomator dump /dev/tty 2>/dev/null \
            | sed 's/UI hierchary dumped to.*//'; }

# artifact_size <vulnId> : bytes of the module's on-device evidence file, or 0
# if it doesn't exist. Used as a second, panel-independent proof surface.
artifact_size() {
  "${ADB[@]}" shell "F='$DEVICE_ARTIFACT_DIR/$1.txt'; [ -f \"\$F\" ] && wc -c < \"\$F\" || echo 0" \
    2>/dev/null | tr -dc '0-9'
}

# app_is_foreground : true iff DVMA owns the currently focused window. Used to
# stop tapping when a module intentionally launched another app/the launcher.
app_is_foreground() {
  "${ADB[@]}" shell dumpsys window 2>/dev/null \
    | grep -i "mCurrentFocus" | grep -q "$PKG/"
}

# app_pid : current pid of the app process (empty if not running).
app_pid() { "${ADB[@]}" shell pidof "$PKG" 2>/dev/null | tr -d '\r'; }

# crashed_since : true iff a FATAL native signal / process death for the app was
# logged since <sinceTsEpoch>. A module whose REAL effect is a native memory
# bug (e.g. unsafe_media_decoding: 32-bit w*h*bpp overflow -> SIGSEGV) kills the
# process before it can render a panel or write its artifact - the crash itself
# is the on-device proof the vulnerable path executed.
crashed_since() {
  local pid="$1"
  "${ADB[@]}" logcat -d -b crash -b main 2>/dev/null \
    | grep -iE "Fatal signal .* \($PKG\)|Fatal signal .*pid $pid|libc *: Fatal signal|Process $PKG .*has died|Force finishing activity $PKG" \
    | grep -q .
}

# tap_id <resource-id> : tap the center of the element with that resource-id.
tap_id() {
  local id="$1" xml bounds cx cy
  for _ in 1 2 3 4 5; do
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

# has_id <resource-id-regex> : true if a matching element is on screen.
has_id() { _dump | grep -qE "resource-id=\"$1\""; }

# tap_desc <content-desc> : tap the center of the element with that exact
# content-description (used for controls that have no stable resource-id, e.g.
# the search field's "Clear search" X icon and the "Expand all" toggle).
tap_desc() {
  local desc="$1" xml bounds cx cy
  xml="$(_dump || true)"
  bounds="$(printf '%s' "$xml" \
    | grep -o "content-desc=\"$desc\"[^>]*bounds=\"[^\"]*\"" \
    | grep -o 'bounds="[^"]*"' | head -1 \
    | grep -o '[0-9]\+' | paste -sd' ' -)"
  # content-desc may appear before bounds in some nodes; try the reverse order.
  if [[ -z "$bounds" ]]; then
    bounds="$(printf '%s' "$xml" \
      | grep -o "bounds=\"[^\"]*\"[^>]*content-desc=\"$desc\"" \
      | grep -o 'bounds="[^"]*"' | head -1 \
      | grep -o '[0-9]\+' | paste -sd' ' -)"
  fi
  [[ -n "$bounds" ]] || return 1
  cx=$(( ( $(echo "$bounds" | cut -d' ' -f1) + $(echo "$bounds" | cut -d' ' -f3) ) / 2 ))
  cy=$(( ( $(echo "$bounds" | cut -d' ' -f2) + $(echo "$bounds" | cut -d' ' -f4) ) / 2 ))
  "${ADB[@]}" shell input tap "$cx" "$cy"
}

# tap_all_actions : tap every action button currently on screen, by its center,
# so multi-button screens (vuln + secure) all fire. Prefix is parsed from
# test_ids.dart, not hardcoded.
# tap_all_actions : tap EVERY action button on the screen, including ones below
# the fold. Multi-button modules (e.g. RAG: seed -> ingest -> ask) place later
# buttons under TextFields; tapping near a field can raise the soft keyboard and
# cover lower buttons, and each tap re-renders the screen (labels change, panels
# appear) which shifts every coordinate. So we tap ONE not-yet-tapped action per
# iteration, then take a FRESH dump, dismissing the keyboard first so nothing is
# occluded. We scroll down when nothing new is visible. Ids are tracked so we
# never double-fire; order is top-to-bottom so ordered flows run in sequence.
tap_all_actions() {
  local xml line id bounds cx cy done_ids=" " tapped=0 next_line
  for _ in $(seq 1 24); do
    # Guard: only act while DVMA is actually foreground. Some modules launch an
    # external Activity/intent (that IS the vuln), which puts the launcher or
    # another app in front - if we kept tapping we'd fire taps on the launcher
    # (and get stuck). The moment we're no longer on DVMA, the demo already ran,
    # so stop tapping and let the caller assert via the panel/artifact.
    if ! app_is_foreground; then break; fi
    # A soft keyboard (raised by tapping a module TextField) can cover lower
    # buttons. Dismiss it the way the app itself does - the screens wire
    # `onTap: FocusManager.primaryFocus?.unfocus()`, so a tap on neutral space
    # (just under the app bar, clear of any control) drops focus + keyboard with
    # NO text edit and NO navigation. We deliberately avoid KEYCODE_BACK/ESCAPE:
    # BACK would delete text or pop the demo screen and corrupt the next
    # module's search field. Only tap when DVMA is foreground (guarded above).
    if "${ADB[@]}" shell dumpsys input_method 2>/dev/null | grep -q "mInputShown=true"; then
      "${ADB[@]}" shell input tap 540 220 >/dev/null 2>&1   # neutral spot -> app's unfocus handler
      sleep 0.3
    fi
    xml="$(_dump || true)"
    # First not-yet-tapped action node in document (top-to-bottom) order.
    next_line=""
    while IFS= read -r line; do
      id="$(printf '%s' "$line" | grep -o "resource-id=\"[^\"]*\"" | head -1 \
        | sed 's/resource-id="//; s/"$//')"
      [[ -z "$id" ]] && continue
      case "$done_ids" in *" $id "*) continue ;; esac
      next_line="$line"; break
    done < <(printf '%s' "$xml" | grep -o "resource-id=\"${ACTION_PREFIX}[^\"]*\"[^>]*bounds=\"[^\"]*\"")

    if [[ -z "$next_line" ]]; then
      # Nothing new on this screen - try scrolling to reveal buttons below fold.
      "${ADB[@]}" shell input swipe 540 1600 540 700 250 >/dev/null 2>&1
      sleep 0.5
      xml="$(_dump || true)"
      while IFS= read -r line; do
        id="$(printf '%s' "$line" | grep -o "resource-id=\"[^\"]*\"" | head -1 \
          | sed 's/resource-id="//; s/"$//')"
        [[ -z "$id" ]] && continue
        case "$done_ids" in *" $id "*) continue ;; esac
        next_line="$line"; break
      done < <(printf '%s' "$xml" | grep -o "resource-id=\"${ACTION_PREFIX}[^\"]*\"[^>]*bounds=\"[^\"]*\"")
      [[ -z "$next_line" ]] && break   # truly nothing left -> done
    fi

    id="$(printf '%s' "$next_line" | grep -o "resource-id=\"[^\"]*\"" | head -1 \
      | sed 's/resource-id="//; s/"$//')"
    bounds="$(printf '%s' "$next_line" | grep -o 'bounds="[^"]*"' | head -1 \
      | grep -o '[0-9]\+' | paste -sd' ' -)"
    [[ -z "$bounds" ]] && { done_ids+="$id "; continue; }
    cx=$(( ( $(echo "$bounds" | cut -d' ' -f1) + $(echo "$bounds" | cut -d' ' -f3) ) / 2 ))
    cy=$(( ( $(echo "$bounds" | cut -d' ' -f2) + $(echo "$bounds" | cut -d' ' -f4) ) / 2 ))
    "${ADB[@]}" shell input tap "$cx" "$cy"
    done_ids+="$id "
    tapped=$((tapped+1))
    "${ADB[@]}" shell "cmd activity idle-maintenance >/dev/null 2>&1 || true" >/dev/null 2>&1
    sleep 0.6
  done
  echo "$tapped"
}

# field_text : echo the current text in the search field (empty if none).
# NOTE: the typed value lives in the focused android.widget.EditText node, NOT
# on the node carrying resource-id="dvma_search_field" (that is a wrapper View
# with empty text). So we read the EditText's text attribute directly.
field_text() {
  _dump | grep -o 'class="android.widget.EditText"[^>]*text="[^"]*"' \
    | grep -o 'text="[^"]*"' | tail -1 | sed 's/^text="//; s/"$//'
}
# The EditText appears with text BEFORE or AFTER the class= attribute depending
# on attribute order; also try the reverse ordering.
field_text_any() {
  local t
  t="$(field_text)"
  if [[ -z "$t" ]]; then
    t="$(_dump | grep -o 'text="[^"]*"[^>]*class="android.widget.EditText"' \
        | grep -o 'text="[^"]*"' | tail -1 | sed 's/^text="//; s/"$//')"
  fi
  echo "$t"
}

# clear_search : wipe the query deterministically and VERIFY it's empty. Focus
# the field, tap the app's built-in "Clear search" (X) icon (present only while
# the query is non-empty), and confirm the field text is gone; fall back to
# select-all + delete if the X tap didn't take. Retries a few times.
clear_search() {
  local cur
  for _ in 1 2 3 4; do
    cur="$(field_text_any)"                # tolerate either attribute order
    [[ -z "$cur" ]] && return 0            # already empty
    tap_id "$SEARCH_FIELD" >/dev/null 2>&1 || true
    if ! tap_desc "Clear search"; then
      # No X found - delete by length as a fallback.
      "${ADB[@]}" shell input keyevent KEYCODE_MOVE_END >/dev/null 2>&1
      local i=0
      while (( i < ${#cur} + 2 )); do "${ADB[@]}" shell input keyevent KEYCODE_DEL >/dev/null 2>&1; i=$((i+1)); done
    fi
    sleep 0.5
  done
  [[ -z "$(field_text_any)" ]]
}

# type_query <text> : type into the (already focused) search field and confirm
# the field contains EXACTLY it (not merely "ends with" - a leftover prefix from
# an incomplete clear would still substring-match and open the wrong/no row).
type_query() {
  local q="$1" cur
  for _ in 1 2 3; do
    "${ADB[@]}" shell input text "$q" >/dev/null 2>&1
    sleep 0.7
    cur="$(field_text_any)"
    [[ "$cur" == "$q" ]] && return 0       # exact match - clean field, right query
    # Wrong/partial content (leftover prefix or dropped chars): hard-clear + retry.
    clear_search >/dev/null 2>&1 || true
    tap_id "$SEARCH_FIELD" >/dev/null 2>&1 || true
  done
  return 1
}

# home : return DVMA to a clean, searchable home (no edge gestures). Robust to
# a module having launched another app/the launcher: we bring DVMA's task to
# the front, and if a detail screen is still open we pop it until the search
# field (home) is visible.
home() {
  for _ in 1 2 3; do
    "${ADB[@]}" shell am start -n "$PKG/.MainActivity" >/dev/null 2>&1
    wait_for "$SEARCH_FIELD" 6 && return 0
    # A demo/detail screen is still on top - pop it, then re-check.
    "${ADB[@]}" shell input keyevent KEYCODE_BACK >/dev/null 2>&1
    wait_for "$SEARCH_FIELD" 4 && return 0
  done
  return 1
}

# wait_for <resource-id-regex> <max_seconds> : poll the tree until present.
wait_for() {
  local pat="$1" max="${2:-8}" i=0
  while (( i < max )); do
    has_id "$pat" && return 0
    sleep 1; i=$((i+1))
  done
  return 1
}

# Preflight
say "Preflight"
note "adb: $ADB_PATH"
"${ADB[@]}" get-state >/dev/null 2>&1 || die "no device via adb (connect a device or boot an emulator; authorize the USB prompt)" "getting-started/prerequisites/#android-device-physical"
note "device: $("${ADB[@]}" get-serialno)"
"${ADB[@]}" shell pm path "$PKG" >/dev/null 2>&1 || die "$PKG not installed - build & install first" "getting-started/build-and-flavors/"

# Android-applicable module ids from the manifest (the authoritative list).
# We only need the id; row/screen ids are derived from the parsed prefixes so
# there is no second source of truth to drift. (Read into an array without
# `mapfile`, which is absent on macOS's bash 3.2.)
MODULE_IDS=()
while IFS= read -r line; do
  [[ -n "$line" ]] && MODULE_IDS+=("$line")
done < <(python3 - "$MANIFEST" "${ONLY:-}" <<'PY'
import json, sys
manifest, only = sys.argv[1], sys.argv[2]
allow = {s for s in only.split(',') if s} if only else None
for m in json.load(open(manifest))['modules']:
    if 'android' not in m.get('platforms', ['android', 'ios']):
        continue
    if allow is not None and m['id'] not in allow:
        continue
    print(m['id'])
PY
)
note "modules to verify: ${#MODULE_IDS[@]}"
[[ "${#MODULE_IDS[@]}" -gt 0 ]] || { bad "no modules parsed from $MANIFEST"; exit 1; }

mkdir -p "$ARTIFACTS"
: > "$SUMMARY"

"${ADB[@]}" shell am force-stop "$PKG" >/dev/null 2>&1 || true
home || { bad "could not reach DVMA home"; exit 1; }

PASS=0; NOEV=0; NAV=0
"${ADB[@]}" logcat -c >/dev/null 2>&1 || true

for id in "${MODULE_IDS[@]}"; do
  rowId="${ROW_PREFIX}${id}"
  screenId="${SCREEN_PREFIX}${id}"

  # Navigate by SEARCH. Order matters: reach home, FOCUS the field, then CLEAR
  # any leftover query from the previous module (the query persists across the
  # module screen), VERIFY it's empty, then type this id and verify it landed.
  # Without the verified clear, ids get appended and the row is never opened.
  home >/dev/null || true
  if ! tap_id "$SEARCH_FIELD"; then
    bad "$id: search field not found"; echo "NAV-FAIL $id" >> "$SUMMARY"; NAV=$((NAV+1)); continue
  fi
  if ! clear_search; then
    bad "$id: could not clear search field"; echo "NAV-FAIL $id" >> "$SUMMARY"; NAV=$((NAV+1)); continue
  fi
  if ! type_query "$id"; then
    bad "$id: search text did not register"; echo "NAV-FAIL $id" >> "$SUMMARY"; NAV=$((NAV+1)); continue
  fi
  wait_for "$rowId" 5 >/dev/null 2>&1 || true

  if ! tap_id "$rowId"; then
    bad "$id: row not found after search"; echo "NAV-FAIL $id" >> "$SUMMARY"; NAV=$((NAV+1)); continue
  fi
  if ! wait_for "$screenId" 8; then
    bad "$id: demo screen did not open"; echo "NAV-FAIL $id" >> "$SUMMARY"; NAV=$((NAV+1)); continue
  fi

  # Record the on-device artifact size BEFORE triggering, so we can detect a
  # module that proves itself by writing/appending its <vulnId>.txt even when
  # no evidence_* panel is visible (it navigated away or finished async).
  before_bytes="$(artifact_size "$id")"; before_bytes="${before_bytes:-0}"
  before_pid="$(app_pid)"
  "${ADB[@]}" logcat -c -b crash >/dev/null 2>&1 || true   # fresh crash buffer

  # Trigger the vulnerable path: tap all action buttons.
  tapped="$(tap_all_actions)"

  # Verify on ANY of the app's real on-device evidence surfaces:
  #   1) an evidence_* panel renders (synchronous, on-screen), or
  #   2) the pullable <vulnId>.txt artifact appears/grows (async or navigated
  #      away - give the panel a longer poll first, then check the file), or
  #   3) the app process crashed with a FATAL native signal (a module whose real
  #      effect IS memory corruption, e.g. unsafe_media_decoding's integer
  #      overflow -> SIGSEGV, dies before it can render/record - the crash is
  #      itself proof the vulnerable native path ran).
  if wait_for "${EVIDENCE_PREFIX}.*" 10; then
    ok "$id: VERIFIED (tapped $tapped action(s), evidence panel present)"
    echo "PASS $id (tapped $tapped)" >> "$SUMMARY"; PASS=$((PASS+1))
  elif after_bytes="$(artifact_size "$id")"; [[ "${after_bytes:-0}" -gt "$before_bytes" ]]; then
    ok "$id: VERIFIED (tapped $tapped, artifact file grew ${before_bytes}->${after_bytes} bytes)"
    echo "PASS $id (tapped $tapped, artifact +$((after_bytes-before_bytes))B)" >> "$SUMMARY"; PASS=$((PASS+1))
  elif crashed_since "$before_pid"; then
    ok "$id: VERIFIED (tapped $tapped, app crashed with a fatal signal - memory-corruption path executed)"
    echo "PASS $id (tapped $tapped, native crash)" >> "$SUMMARY"; PASS=$((PASS+1))
  else
    bad "$id: NO evidence panel, artifact, or crash after tapping $tapped action(s)"
    echo "NO-EVIDENCE $id (tapped $tapped)" >> "$SUMMARY"; NOEV=$((NOEV+1))
  fi

  "${ADB[@]}" shell input keyevent KEYCODE_BACK >/dev/null 2>&1
done

say "Verification complete"
note "PASS (evidence present) : $PASS"
note "NO-EVIDENCE             : $NOEV"
note "NAV-FAIL                : $NAV"
note "summary written to      : $SUMMARY"
if [[ "$NOEV" -gt 0 ]]; then
  say "Modules that produced NO on-device evidence (review these):"
  grep '^NO-EVIDENCE' "$SUMMARY" | sed 's/^/  /'
fi
[[ "$NOEV" -eq 0 && "$NAV" -eq 0 ]]
