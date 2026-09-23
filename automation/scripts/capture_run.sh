#!/usr/bin/env bash
#
# DVMA dynamic-analysis capture harness (Android).
#
# Runs the UiAutomator "walk every module" instrumentation test against a
# connected device/emulator while capturing what each module ACTUALLY does:
#
#   * logcat lines under the DVMA-EVIDENCE tag (the shared evidence sink),
#   * the per-module artifact files the sink writes (adb-pullable),
#   * the app's real on-device state: shared_prefs XML, SQLite databases,
#     temp/backup/external files (pulled via `run-as`),
#   * network flows captured by automation/scripts/capture_listener.py (if run).
#
# It then assembles a single Markdown report: automation/artifacts/report.md
#
# FOR AUTHORIZED TRAINING USE ONLY.
#
# Usage:
#   # 1) (optional) in another terminal, start the capture listener:
#   python3 automation/scripts/capture_listener.py --https 8443
#   # 2) build a DEBUG apk with androidTest wired in and run the harness:
#   automation/scripts/capture_run.sh
#
# Env overrides:
#   PKG           app id (default com.dvma)
#   SERIAL        adb -s target (default: first device)
#   ARTIFACTS     output dir (default automation/artifacts)
#   ATTACKER      set to 1 to also build/install the com.dvma.attacker companion
#                 app and capture the cross-app leaks it harvests
#                 (cross_app_otp_credential_leak vertical).
set -euo pipefail

PKG="${PKG:-com.dvma}"
ATTACKER_PKG="com.dvma.attacker"
ATTACKER_DIR="companion/dvma-attacker"
ARTIFACTS="${ARTIFACTS:-automation/artifacts}"
ADB=(adb)
if [[ -n "${SERIAL:-}" ]]; then ADB=(adb -s "$SERIAL"); fi

mkdir -p "$ARTIFACTS"/{prefs,databases,files,screenshots,attacker}
LOGCAT_RAW="$ARTIFACTS/logcat_evidence.txt"
ATTACKER_LOG="$ARTIFACTS/attacker/logcat_attacker.txt"
REPORT="$ARTIFACTS/report.md"

echo "[harness] target package: $PKG"
"${ADB[@]}" get-state >/dev/null || { echo "[harness] no device via adb"; exit 1; }

# Optionally build + install the standalone companion attacker app. It is a
# separate package/UID/signature, so it can only harvest what DVMA genuinely
# leaks across the process boundary (that is the whole point of the cross-app
# verification).
if [[ "${ATTACKER:-0}" == "1" ]]; then
  echo "[harness] building companion attacker apk ($ATTACKER_PKG)"
  ( cd "$ATTACKER_DIR" && ./gradlew :app:assembleDebug ) \
    || { echo "[harness] attacker build failed"; exit 1; }
  ATTACKER_APK="$ATTACKER_DIR/app/build/outputs/apk/debug/app-debug.apk"
  echo "[harness] installing attacker apk"
  "${ADB[@]}" install -r "$ATTACKER_APK" >/dev/null
  # Grant notification permission (Android 13+) so the harvest foreground
  # service can post its ongoing notification without prompting.
  "${ADB[@]}" shell pm grant "$ATTACKER_PKG" android.permission.POST_NOTIFICATIONS \
    2>/dev/null || true
  # Clear any prior attacker capture file (external files dir).
  "${ADB[@]}" shell rm -f \
    "/sdcard/Android/data/$ATTACKER_PKG/files/attacker_captures.txt" 2>/dev/null || true
  # Launch its activity, which starts the OtpHarvestService foreground service.
  # That service keeps a runtime receiver registered so the attacker harvests
  # DVMA's UNPROTECTED implicit broadcast even while DVMA is foreground
  # (Android 8+ blocks implicit-broadcast delivery to manifest receivers).
  "${ADB[@]}" shell am start -n "$ATTACKER_PKG/.AttackerActivity" >/dev/null 2>&1 || true
  sleep 2
  echo "[harness] capturing attacker logcat -> $ATTACKER_LOG"
  "${ADB[@]}" logcat -s DVMA-ATTACKER:* > "$ATTACKER_LOG" 2>/dev/null &
  ATTACKER_LOGCAT_PID=$!
  trap 'kill $ATTACKER_LOGCAT_PID 2>/dev/null || true' EXIT
fi

echo "[harness] clearing prior logcat + app evidence dir"
"${ADB[@]}" logcat -c || true
"${ADB[@]}" shell run-as "$PKG" sh -c 'rm -rf files/dvma-artifacts 2>/dev/null' || true

# Start a background logcat capture. Flutter routes developer.log(name:) under
# the "flutter" tag with the name in the message, so we capture flutter lines
# and the report parser greps for the DVMA-EVIDENCE marker within them.
echo "[harness] starting logcat capture -> $LOGCAT_RAW"
"${ADB[@]}" logcat -s flutter:* > "$LOGCAT_RAW" 2>/dev/null &
LOGCAT_PID=$!
trap 'kill $LOGCAT_PID 2>/dev/null || true' EXIT

# Run the UiAutomator walk-all instrumentation (opt-in androidTest build).
echo "[harness] building + running walk-all instrumentation (this takes a while)"
pushd android >/dev/null
# Select the walk-all class via the instrumentation runner argument. (The
# JVM-only `--tests` filter isn't accepted on connectedAndroidTest by this
# AGP.)
./gradlew -PdvmaAndroidTest=true \
  :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.dvma.DvmaWalkAllModulesTest \
  || echo "[harness] (instrumentation returned non-zero; continuing to collect artifacts)"
popd >/dev/null

# Give the sink a moment to flush.
sleep 2
kill $LOGCAT_PID 2>/dev/null || true

echo "[harness] pulling on-device artifacts"
# 1) sink artifact files (external files dir, no root needed). Pull the dir
# CONTENTS into ARTIFACTS/files (the trailing /. avoids a nested dir level).
EXT="/sdcard/Android/data/$PKG/files/dvma-artifacts"
"${ADB[@]}" pull "$EXT/." "$ARTIFACTS/files" 2>/dev/null || echo "[harness] (no sink artifact dir)"

# 2) shared_prefs + databases from the private sandbox (debuggable -> run-as)
for sub in shared_prefs databases; do
  dest="$ARTIFACTS/${sub/shared_prefs/prefs}"
  "${ADB[@]}" shell run-as "$PKG" sh -c "ls $sub 2>/dev/null" | while read -r f; do
    [[ -z "$f" ]] && continue
    "${ADB[@]}" shell run-as "$PKG" cat "$sub/$f" > "$dest/$f" 2>/dev/null || true
    echo "[harness]   pulled $sub/$f"
  done
done

# 3) instrumentation screenshots (written by the walk-all test)
"${ADB[@]}" pull "$EXT/../dvma-artifacts" "$ARTIFACTS/screenshots" 2>/dev/null || true

# 4) companion attacker captures (separate app sandbox), if it ran
if [[ "${ATTACKER:-0}" == "1" ]]; then
  sleep 1
  kill "${ATTACKER_LOGCAT_PID:-0}" 2>/dev/null || true
  echo "[harness] pulling attacker capture file"
  ATTACKER_EXT="/sdcard/Android/data/$ATTACKER_PKG/files/attacker_captures.txt"
  "${ADB[@]}" pull "$ATTACKER_EXT" "$ARTIFACTS/attacker/attacker_captures.txt" 2>/dev/null \
    || echo "[harness] (no attacker capture file - did DVMA fire the broadcast?)"
fi

echo "[harness] assembling report -> $REPORT"
python3 automation/scripts/build_capture_report.py \
  --artifacts "$ARTIFACTS" \
  --logcat "$LOGCAT_RAW" \
  --flows "automation/artifacts/capture_flows.jsonl" \
  --attacker-log "$ATTACKER_LOG" \
  --out "$REPORT"

echo "[harness] done. Report: $REPORT"
