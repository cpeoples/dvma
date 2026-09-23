#!/usr/bin/env bash
#
# DVMA dynamic-analysis capture harness (iOS Simulator).
#
# The iOS analogue of capture_run.sh. Runs the native XCUITest "walk every
# module" suite (RunnerUITests) against a booted Simulator while capturing what
# each module ACTUALLY does, then assembles a Markdown report.
#
# WHAT IT PROVES (and what it can't) - the three tiers:
#   * Tier A (most storage/crypto/auth/network/input modules + the Keychain
#     modules): the real insecure I/O is pure-Dart and IDENTICAL to Android - a
#     real UserDefaults plist / SQLite db / temp file write, a real socket, real
#     ciphertext. This harness pulls those REAL artifacts from the app's
#     Documents container and the os_log stream, so these findings are verified
#     for real on iOS.
#   * Tier B-real (the 5 resilience modules): ios/Runner/DvmaNativeProbes.swift
#     implements REAL Swift probes (jailbreak markers + sandbox write, sysctl
#     P_TRACED, simulator env, dyld Frida-image scan + port 27042, embedded
#     profile digest) and the Dart bridge is now Android||iOS, so the native
#     signal is real (the module still gates on a bypassable client-side bool).
#   * Tier B-nosim (system_provider, the IPC groups, cross-app OTP): these model
#     Android-only trust boundaries (implicit broadcasts, exported components,
#     ContentProviders, Binder) with NO iOS equivalent, so on iOS the bridge
#     returns null and the module runs its in-Dart SIMULATION - intentionally
#     not faked (see DvmaNativeProbes.swift; those methods stay not-implemented).
#   * Tier C (iOS-only App Intents / Shortcuts / App Group modules): in-Dart sims
#     today; the App Group shared-container read is the one real-probe candidate.
#     (Full per-module breakdown: docs/ios_parity_audit.md.)
#
# The evidence sink (lib/core/evidence_sink.dart) writes, on iOS, to the app's
# Documents dir: Documents/dvma-artifacts/<vulnId>.txt, and mirrors every record
# to os_log under the "DVMA-EVIDENCE" name. On the SIMULATOR the container is a
# real directory on your Mac (xcrun simctl get_app_container), so NO jailbreak,
# NO device backup, and NO adb-equivalent is needed - just simctl.
#
# FOR AUTHORIZED TRAINING USE ONLY. Run on a disposable Simulator only.
#
# Usage (from repo root):
#   automation/scripts/capture_run_ios.sh
#
# Env overrides:
#   BUNDLE_ID   app bundle id            (default com.dvma)
#   UDID        target simulator udid    (default: the booted one, else a new
#                                          iPhone from DEVICE_NAME)
#   DEVICE_NAME simulator to boot if none is booted (default "iPhone 17")
#   SCHEME      xcode scheme             (default Runner)
#   FLAVOR      dart-define-from-file    (default config/flavors/full.json)
#   ARTIFACTS   output dir              (default automation/artifacts/ios)
#   SKIP_TEST   set to 1 to skip the XCUITest run and only pull existing
#               artifacts (useful when iterating on the report)
set -euo pipefail

BUNDLE_ID="${BUNDLE_ID:-com.dvma}"
DEVICE_NAME="${DEVICE_NAME:-iPhone 17}"
SCHEME="${SCHEME:-Runner}"
FLAVOR="${FLAVOR:-config/flavors/full.json}"
ARTIFACTS="${ARTIFACTS:-automation/artifacts/ios}"
PROJECT="ios/Runner.xcodeproj"

SINK_SUBDIR="dvma-artifacts"          # mirrors DvmaEvidence.artifactDir
LOG_NAME="DVMA-EVIDENCE"              # mirrors DvmaEvidence.logTag
FILES_DIR="$ARTIFACTS/files"
OSLOG_RAW="$ARTIFACTS/oslog_evidence.txt"
REPORT="$ARTIFACTS/report-ios.md"

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

command -v xcrun >/dev/null 2>&1 || die "xcrun not found - install the full Xcode app (not just Command Line Tools)" "getting-started/prerequisites/#host-toolchain"
mkdir -p "$FILES_DIR"

# Resolve / boot a Simulator
say "Resolving Simulator"
resolve_udid() {
  if [[ -n "${UDID:-}" ]]; then echo "$UDID"; return; fi
  # A booted sim, if any.
  local booted
  booted="$(xcrun simctl list devices booted -j 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin)["devices"];
[print(x["udid"]) for v in d.values() for x in v if x.get("state")=="Booted"]' \
    | head -1)"
  if [[ -n "$booted" ]]; then echo "$booted"; return; fi
  # Otherwise pick an available device matching DEVICE_NAME.
  xcrun simctl list devices available -j 2>/dev/null \
    | python3 -c 'import json,sys,os; d=json.load(sys.stdin)["devices"]; name=os.environ["DEVICE_NAME"];
cands=[x["udid"] for v in d.values() for x in v if x.get("isAvailable") and x["name"]==name];
print(cands[0] if cands else "")' | head -1
}
UDID="$(DEVICE_NAME="$DEVICE_NAME" resolve_udid || true)"
[[ -n "$UDID" ]] || { bad "no Simulator found (set UDID= or a valid DEVICE_NAME; see: xcrun simctl list devices)"; exit 1; }
note "simulator udid: $UDID"

STATE="$(xcrun simctl list devices -j | python3 -c 'import json,sys,os;u=os.environ["UDID"];d=json.load(sys.stdin)["devices"];
print(next((x["state"] for v in d.values() for x in v if x["udid"]==u), "Unknown"))' UDID="$UDID" 2>/dev/null || echo Unknown)"
if [[ "$STATE" != "Booted" ]]; then
  note "booting simulator…"
  xcrun simctl boot "$UDID" 2>/dev/null || true
fi
# Bring the Simulator UI up focused on THIS device so you can watch the walk.
open -a Simulator --args -CurrentDeviceUDID "$UDID" 2>/dev/null || open -a Simulator 2>/dev/null || true
note "waiting for boot to complete…"
xcrun simctl bootstatus "$UDID" -b >/dev/null 2>&1 || true
# Verify it actually reached Booted; bail early with a clear message otherwise.
STATE="$(xcrun simctl list devices -j | python3 -c 'import json,sys,os;u=os.environ["UDID"];d=json.load(sys.stdin)["devices"];
print(next((x["state"] for v in d.values() for x in v if x["udid"]==u), "Unknown"))' UDID="$UDID" 2>/dev/null || echo Unknown)"
if [[ "$STATE" != "Booted" ]]; then
  bad "simulator $UDID did not reach Booted (state=$STATE). Try: xcrun simctl boot $UDID; open -a Simulator"
  exit 1
fi
ok "simulator booted: $UDID"

# Ensure the software keyboard shows for text entry. Modern Simulators hide it
# when a Mac hardware keyboard is "connected", which makes XCUITest typeText
# fail with "no keyboard focus" (and pushes the walk onto the paste fallback,
# which visibly flashes the text-magnifier loupe). Disabling the hardware
# keyboard is the documented, reliable fix. Set it on BOTH the shared iPhone
# Simulator prefs (host-side) and the device prefs, then nudge the sim to pick
# it up. Best-effort; ignore errors.
defaults write com.apple.iphonesimulator ConnectHardwareKeyboard -bool false >/dev/null 2>&1 || true
xcrun simctl spawn "$UDID" defaults write com.apple.keyboard.ContinuousPath ContinuousPathEnabled -bool false >/dev/null 2>&1 || true
xcrun simctl spawn "$UDID" defaults write com.apple.Preferences AutomaticMinimizationEnabled -bool false >/dev/null 2>&1 || true

# Build the Flutter config so xcodebuild can assemble the app
say "Generating Flutter config (full flavor)"
flutter build ios --config-only --simulator --dart-define-from-file="$FLAVOR" \
  || { bad "flutter build --config-only failed"; exit 1; }

# Run the XCUITest walk (unless skipped)
if [[ "${SKIP_TEST:-0}" != "1" ]]; then
  say "Running RunnerUITests walk-all (this boots + installs + walks every module)"
  # Stream os_log for the evidence name in the background so we capture the
  # sink's mirrored lines even though the artifact files are the source of truth.
  : > "$OSLOG_RAW"
  ( xcrun simctl spawn "$UDID" log stream --style syslog \
      --predicate "eventMessage CONTAINS \"$LOG_NAME\"" >> "$OSLOG_RAW" 2>/dev/null ) &
  LOG_PID=$!
  trap 'kill $LOG_PID 2>/dev/null || true' EXIT

  # Fresh result bundle each run so we can reliably harvest attachments below.
  RESULT_BUNDLE="$ARTIFACTS/RunnerUITests.xcresult"
  rm -rf "$RESULT_BUNDLE"

  # NOTE: the walk gets its COMPLETE module list from the APP ITSELF at runtime
  # (the hidden `dvma_module_manifest` accessibility node exposes
  # VulnerabilityRegistry.enabledFor as a CSV), so there is no repo-side manifest
  # to keep in sync and nothing to inject here. See DVMAWalkAllModulesUITests.
  #
  # -parallel-testing-enabled NO stops xcodebuild from spinning up a *deleted*
  # "Clone N of …" sim for UI testing; the walk then runs on OUR booted $UDID so
  # its app container (Documents/dvma-artifacts) survives for the pull below.
  # If a future Xcode clones anyway, the .xcresult attachment fallback still
  # recovers the screenshots, so this stays robust either way.
  # Optional targeted subset: if DVMA_MODULE_IDS is set, pass it to the runner
  # as a TEST_RUNNER_-prefixed build setting. Xcode injects it into the runner's
  # ProcessInfo.environment; depending on the Xcode version the prefix is kept
  # or stripped, so resolveModuleIds reads BOTH keys and, when present, walks
  # only this subset (fast targeted runs). Unset -> full app-manifest walk.
  SUBSET_ARG=()
  if [[ -n "${DVMA_MODULE_IDS:-}" ]]; then
    note "walking only DVMA_MODULE_IDS subset: $DVMA_MODULE_IDS"
    SUBSET_ARG=(TEST_RUNNER_DVMA_MODULE_IDS="$DVMA_MODULE_IDS")
  fi

  # Force a fresh compile into a run-local DerivedData dir so the UI-test target
  # (and its subset-selection logic) can never be served stale from a cached
  # build - that once caused a subset run to silently walk all modules.
  DD_DIR="$ARTIFACTS/DerivedData"

  xcodebuild test \
    -project "$PROJECT" \
    -scheme "$SCHEME" \
    -destination "platform=iOS Simulator,id=$UDID" \
    -only-testing:RunnerUITests \
    -parallel-testing-enabled NO \
    -derivedDataPath "$DD_DIR" \
    -resultBundlePath "$RESULT_BUNDLE" \
    ${SUBSET_ARG[@]+"${SUBSET_ARG[@]}"} \
    || note "(xcodebuild test returned non-zero; continuing to collect artifacts)"

  sleep 2
  kill "$LOG_PID" 2>/dev/null || true
  trap - EXIT
else
  note "SKIP_TEST=1 - not running the walk; pulling existing artifacts only"
  RESULT_BUNDLE="$ARTIFACTS/RunnerUITests.xcresult"
fi

# Pull the app's Documents container (the sink's artifact files)
say "Pulling on-simulator artifacts"
CONTAINER="$(xcrun simctl get_app_container "$UDID" "$BUNDLE_ID" data 2>/dev/null || true)"
if [[ -z "$CONTAINER" || ! -d "$CONTAINER" ]]; then
  bad "could not locate the app data container for $BUNDLE_ID on $UDID"
  note "is the app installed? the XCUITest run installs it; re-run without SKIP_TEST=1"
else
  note "app container: $CONTAINER"
  SINK_DIR="$CONTAINER/Documents/$SINK_SUBDIR"
  if [[ -d "$SINK_DIR" ]]; then
    cp -f "$SINK_DIR"/*.txt "$FILES_DIR"/ 2>/dev/null || true
    ok "pulled $(find "$FILES_DIR" -name '*.txt' | wc -l | tr -d ' ') sink artifact file(s) -> $FILES_DIR"
  else
    note "(no $SINK_SUBDIR dir yet - did any module run its real path?)"
  fi
  # Also snapshot the whole Documents + Library/Preferences (UserDefaults plist)
  # so temp/backup/DB-style artifacts and the key-value store are captured too.
  mkdir -p "$ARTIFACTS/container"
  for sub in Documents Library/Preferences; do
    if [[ -d "$CONTAINER/$sub" ]]; then
      dest="$ARTIFACTS/container/${sub//\//_}"
      mkdir -p "$dest"
      cp -Rf "$CONTAINER/$sub/." "$dest"/ 2>/dev/null || true
    fi
  done
  ok "snapshotted Documents + Library/Preferences -> $ARTIFACTS/container"
fi

# Recover per-module screenshots from the .xcresult attachments. The walk test
# attaches a screenshot per opened module. Harvest them regardless
# of where the app container lived (base sim vs. a throwaway clone) so the run
# always yields visual evidence; the sink files come from the container pull
# above and the os_log stream (both real, on-simulator sources).
if [[ -d "${RESULT_BUNDLE:-/nonexistent}" ]]; then
  say "Recovering screenshots from .xcresult attachments"
  ATT_DIR="$ARTIFACTS/screenshots"
  rm -rf "$ATT_DIR"; mkdir -p "$ATT_DIR"
  if xcrun xcresulttool export attachments \
       --path "$RESULT_BUNDLE" --output-path "$ATT_DIR" >/dev/null 2>&1; then
    shots="$(find "$ATT_DIR" -name '*.png' 2>/dev/null | wc -l | tr -d ' ')"
    ok "recovered $shots screenshot(s) -> $ATT_DIR"
  else
    note "(xcresulttool export attachments unavailable; skipping)"
  fi
fi

# Assemble a focused iOS report
say "Assembling report -> $REPORT"
FILES_DIR="$FILES_DIR" OSLOG_RAW="$OSLOG_RAW" REPORT="$REPORT" \
BUNDLE_ID="$BUNDLE_ID" UDID="$UDID" MANIFEST="automation/vuln_manifest.json" \
python3 - <<'PY'
import glob, json, os, re

files_dir = os.environ["FILES_DIR"]
oslog_raw = os.environ["OSLOG_RAW"]
report    = os.environ["REPORT"]
bundle_id = os.environ["BUNDLE_ID"]
udid      = os.environ["UDID"]
manifest  = os.environ["MANIFEST"]

# Which modules surface on iOS (shared + [ios]) - the honest denominator.
ios_mods = {}
try:
    for m in json.load(open(manifest))["modules"]:
        plats = m.get("platforms", ["android", "ios"])
        if "ios" in plats:
            ios_mods[m["id"]] = m
except Exception:
    pass

# Sink artifact files: Documents/dvma-artifacts/<vulnId>.txt, blocks of
# "<iso-ts>\t<kind>\n<artifact...>\n\n".
block = re.compile(r"^\S+\t(?P<kind>[\w-]+)\n(?P<art>.*?)(?=\n\S+\t[\w-]+\n|\Z)",
                   re.MULTILINE | re.DOTALL)
observed = {}
for p in sorted(glob.glob(os.path.join(files_dir, "*.txt"))):
    vuln = os.path.splitext(os.path.basename(p))[0]
    text = open(p, encoding="utf-8", errors="replace").read()
    kinds = [(m.group("kind"), m.group("art").strip().splitlines()[0] if m.group("art").strip() else "")
             for m in block.finditer(text)]
    observed[vuln] = kinds or [("artifact", text.strip().splitlines()[0] if text.strip() else "")]

# os_log evidence lines: "[<vuln>] <kind> :: <artifact>"
line_re = re.compile(r"\[(?P<vuln>[a-z0-9_]+)\]\s+(?P<kind>[\w-]+)\s+::")
oslog_hits = set()
if os.path.exists(oslog_raw):
    for line in open(oslog_raw, encoding="utf-8", errors="replace"):
        mm = line_re.search(line)
        if mm:
            oslog_hits.add(mm.group("vuln"))

total_ios = len(ios_mods) if ios_mods else len(observed)
with_file = sum(1 for v in observed if not ios_mods or v in ios_mods)
out = []
out.append("# DVMA iOS capture report\n")
out.append(f"- Simulator: `{udid}`  •  bundle id: `{bundle_id}`")
out.append(f"- iOS-applicable modules (shared + iOS-only): **{total_ios}**")
out.append(f"- Modules with a REAL pulled artifact file: **{with_file}**")
out.append(f"- Modules seen in os_log (`DVMA-EVIDENCE`): **{len(oslog_hits)}**\n")
out.append("> Tier A modules (pure-Dart real I/O, incl. the Keychain modules) "
           "show a real artifact file below - identical to their Android "
           "behavior. The 5 resilience modules (Tier B-real) emit a REAL native "
           "iOS probe via ios/Runner/DvmaNativeProbes.swift. The remaining "
           "native-bridge modules (system_provider / IPC / cross-app OTP) model "
           "Android-only trust boundaries with no iOS equivalent and run an "
           "in-Dart simulation on purpose. Full per-module tiering: "
           "docs/ios_parity_audit.md.\n")

out.append("## Per-module observed artifacts\n")
ids = sorted(ios_mods) if ios_mods else sorted(observed)
for vuln in ids:
    kinds = observed.get(vuln)
    logged = " · os_log✓" if vuln in oslog_hits else ""
    if kinds:
        out.append(f"### `{vuln}` - artifact file ✓{logged}")
        for kind, first in kinds:
            first = (first[:160] + "…") if len(first) > 160 else first
            out.append(f"- **{kind}** - {first}")
    else:
        seen = " (os_log only - no file)" if vuln in oslog_hits else " (no artifact captured)"
        out.append(f"### `{vuln}`{seen}")
    out.append("")

# Modules that wrote a file but aren't in the manifest slice (defensive).
extras = [v for v in observed if ios_mods and v not in ios_mods]
if extras:
    out.append("## Files not in the iOS manifest slice\n")
    for v in sorted(extras):
        out.append(f"- `{v}`")

open(report, "w", encoding="utf-8").write("\n".join(out) + "\n")
print(f"  wrote {report}")
PY

ok "done. Report: $REPORT"
note "Sink files : $FILES_DIR"
note "Container  : $ARTIFACTS/container   (Documents + Library/Preferences snapshot)"
note "os_log     : $OSLOG_RAW"
