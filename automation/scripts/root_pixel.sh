#!/usr/bin/env bash
#
# DVMA - headless Magisk rooting pipeline for Pixel test devices.
#
# Patches a stock boot image for Magisk WITHOUT opening the Magisk GUI, by
# running Magisk's own on-device patcher (assets/boot_patch.sh, extracted from
# the Magisk APK) over `adb shell`. This is exactly what the app's
# "Install -> Select and Patch a File" button does under the hood.
#
# The pipeline can run end-to-end and unattended on an ALREADY-UNLOCKED, ALREADY-
# AUTHORIZED device:
#   --fetch-magisk  : download + verify the Magisk APK (signer-cert pinned).
#   --fetch-image   : detect the device's EXACT factory build, download the
#                     matching Google factory image (via the Flash Tool API),
#                     verify its SHA-256 prefix, and extract the right partition
#                     (init_boot/boot).
#   (patch)         : run Magisk's on-device patcher over adb (always).
#   --flash         : DESTRUCTIVE - fastboot flash the patched partition and
#                     verify root. Typed confirmation unless --yes is given.
#
# DEFAULT SCOPE stays patch-only and non-destructive: without --flash the script
# produces a patched image (and, with --boot-test, TEMPORARILY boots it from RAM
# to sanity-check root) but NEVER writes to a partition. --flash is the single
# explicit switch that turns on the writing step.
#
# WHAT CANNOT BE ZERO-TOUCH (hardware / OS policy - no script can do these):
#   * Bootloader unlock (`fastboot flashing unlock`) needs a PHYSICAL volume-key
#     confirmation on the device and FACTORY-WIPES it. One-time, per device.
#   * The first USB-debugging authorization is an on-device "Allow?" tap. After
#     you tick "always allow" (or pre-seed adb keys) later runs are touch-free.
#   * Some Pixels also show an on-screen confirm for fastboot boot/flash.
# So the realistic ceiling is "one-tap enroll, then fully unattended".
#
# PREREQS (see README "Rooting Android & jailbreaking iOS"):
#   * Bootloader ALREADY unlocked on the target device (see above).
#   * `adb`, `fastboot`, `unzip`, and `curl` on PATH. `apksigner` or `keytool`
#     is used to verify the Magisk signer cert.
#   * If you skip --fetch-image, supply --image (the STOCK partition image from
#     your EXACT factory build, https://developers.google.com/android/images).
#     Which partition depends on the device's LAUNCH Android version, not model:
#       - Pixel 6 / 6 Pro / 6a (bluejay/oriole/raven, launched A12): boot.img
#       - Pixel 7/8/9/10/11 and up (launched A13+, GKI 2.0):         init_boot.img
#     (--fetch-image auto-detects and extracts the right one for any Pixel.)
#
# FOR AUTHORIZED TRAINING USE ONLY. Root a disposable TEST device only - never a
# daily driver and never a device holding real data. Always patch the image ON
# the device you're rooting; never flash someone else's patched image.
#
# Usage (from repo root):
#   # classic patch-only (you supply both inputs):
#   automation/scripts/root_pixel.sh --apk Magisk-v30.7.apk --image init_boot.img
#   # fully autonomous on an unlocked+authorized device (fetch, patch, flash):
#   automation/scripts/root_pixel.sh --fetch-magisk --fetch-image --flash --yes
#   # fetch everything but stop before writing (safe dry pipeline):
#   automation/scripts/root_pixel.sh --fetch-magisk --fetch-image --boot-test
#   # recover a bricked device to stock (re-flash the full factory image):
#   automation/scripts/root_pixel.sh --recover            # or --recover=<build-id> / --yes
#
# Flags:
#   --apk    PATH   Magisk .apk to extract the patcher binaries from
#   --fetch-magisk[=vTAG]
#                   download the Magisk APK from the OFFICIAL GitHub releases
#                   (latest, or the given vTAG) instead of --apk. VERIFIED before
#                   use: signer cert must match the pinned topjohnwu key, and, if
#                   --sha256 is set, the file hash too. Aborts on mismatch.
#                   Provide EITHER --apk OR --fetch-magisk, not both.
#   --sha256 HEX    optional expected SHA-256 of the fetched/supplied APK.
#   --image  PATH   stock boot image to patch: boot.img on Pixel 6/6a, else
#                   init_boot.img (Pixel 7/8/9/10/11+). Required unless
#                   --fetch-image is given; the partition is inferred from the
#                   filename (…init_boot… / …boot…).
#   --fetch-image[=BUILD]
#                   auto-detect the connected device + its exact build and
#                   download the matching Google FACTORY image (via the Flash
#                   Tool API), verify its SHA-256 prefix, and extract the correct
#                   partition image (auto-detected from the package - any Pixel).
#                   Optionally pin an explicit BUILD id (e.g. bp1a.250505.005).
#                   Provide EITHER --image OR --fetch-image, not both.
#   --flash         DESTRUCTIVE. After patching, fastboot flash the patched image
#                   to the device's root partition and verify `su -c id`. Asks for
#                   a typed confirmation first unless --yes is present.
#   --auto-finalize After flashing, best-effort UI automation of Magisk's ONE-TIME
#                   enablement: taps OK on "Requires additional setup" (rides the
#                   reboot) and turns ON the shell (com.android.shell) su switch in
#                   the Superuser tab, then persists it. Version-fragile; falls
#                   back to printed manual steps if the app layout doesn't match.
#   --recover[=BUILD]
#                   DESTRUCTIVE, STANDALONE. Full-brick recovery: re-download +
#                   SHA-256-verify the matching Google FACTORY image and run its
#                   bundled flash-all to restore EVERY partition to stock (wipes
#                   data, rewrites both A/B slots). Optionally pin BUILD; else the
#                   newest listed build for the device. Typed confirmation unless
#                   --yes. Does NOT patch/root - don't combine with the root flags.
#                   Works from a booted device OR one only reachable in fastboot.
#   --yes | -y      skip the interactive confirmation for --flash (unattended).
#   --serial SERIAL target this exact device (adb -s). Required form when more
#                   than one device/emulator is connected; otherwise optional.
#   --keep-downloads[=DIR]
#                   keep AND REUSE the fetched Magisk APK + factory image in a
#                   persistent cache (normally they live in a temp dir deleted on
#                   exit). Default DIR ./dvma-downloads. On repeat runs a cached
#                   factory image whose SHA-256 prefix verifies is reused (no
#                   re-download); interrupted downloads resume. Handy for
#                   iterating, auditing, or offline re-runs.
#   --out    PATH   where to write the patched image  (default ./magisk_patched.img)
#   --arch   ABI    device ABI for the magisk binaries (default arm64-v8a)
#   --boot-test     after patching, `fastboot boot` the image (temporary root,
#                   nothing written) and check `su -c id`, then leave you booted.
#   -h | --help     show this help
#
set -euo pipefail

note() { printf '\033[1;36m[root_pixel]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[root_pixel]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[root_pixel] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# adb/fastboot wrappers that pin the chosen device serial (set after preflight
# device selection). Every adb/fastboot call in this script goes through these,
# so a multi-device host never targets the wrong device. Real binaries are
# reached via `command` to avoid recursion.
adb()      { if [[ -n "${SERIAL:-}" ]]; then command adb -s "$SERIAL" "$@"; else command adb "$@"; fi; }
fastboot() { if [[ -n "${SERIAL:-}" ]]; then command fastboot -s "$SERIAL" "$@"; else command fastboot "$@"; fi; }

# APK verification. Compute an APK's signer-certificate SHA-256 (uppercase,
# colon-separated),
# preferring apksigner and falling back to keytool over the PKCS#7 block. Prints
# the digest, or nothing if no tool is available.
_apk_signer_sha256() {
  local apk="$1"
  if command -v apksigner >/dev/null 2>&1; then
    apksigner verify --print-certs "$apk" 2>/dev/null \
      | sed -n 's/.*SHA-256 digest: *\([0-9a-fA-F]*\).*/\1/p' \
      | head -1 \
      | tr '[:lower:]' '[:upper:]' \
      | sed 's/../&:/g; s/:$//'
    return 0
  fi
  if command -v keytool >/dev/null 2>&1; then
    local d certblk
    d="$(mktemp -d)"
    unzip -o -q "$apk" -d "$d" 'META-INF/*' 2>/dev/null || true
    certblk="$(ls "$d"/META-INF/*.RSA "$d"/META-INF/*.EC "$d"/META-INF/*.DSA 2>/dev/null | head -1)"
    if [[ -n "$certblk" ]]; then
      keytool -printcert -file "$certblk" 2>/dev/null \
        | sed -n 's/.*SHA256: *\([0-9A-F:]*\).*/\1/p' | head -1
    fi
    rm -rf "$d"
    return 0
  fi
}

# Verify a Magisk APK: signer cert must match the pinned release key, and, when
# --sha256 is set, the file hash must match too. Fails closed.
verify_apk() {
  local apk="$1" ok=1

  if [[ -n "$EXPECT_SHA256" ]]; then
    local got exp
    got="$(shasum -a 256 "$apk" 2>/dev/null | awk '{print $1}')"
    [[ -z "$got" ]] && got="$(sha256sum "$apk" 2>/dev/null | awk '{print $1}')"
    got="$(printf '%s' "$got" | tr '[:upper:]' '[:lower:]')"
    exp="$(printf '%s' "$EXPECT_SHA256" | tr '[:upper:]' '[:lower:]')"
    if [[ -n "$got" && "$got" == "$exp" ]]; then
      note "sha256 OK ($got)"
    else
      warn "sha256 MISMATCH: expected $EXPECT_SHA256, got ${got:-<none>}"
      ok=0
    fi
  fi

  local signer
  signer="$(_apk_signer_sha256 "$apk")"
  if [[ -z "$signer" ]]; then
    warn "no apksigner/keytool on PATH - cannot verify the signer certificate."
    if [[ -n "$EXPECT_SHA256" ]]; then
      warn "proceeding on the --sha256 pin alone."
    else
      warn "install Android build-tools (apksigner) or a JDK (keytool), or pass"
      warn "--sha256 to pin the file hash. Refusing an unverified root payload."
      ok=0
    fi
  elif [[ "$signer" == "$MAGISK_SIGNER_SHA256" ]]; then
    note "signer cert OK (topjohnwu release key)."
  else
    warn "signer cert MISMATCH - not the pinned Magisk release key."
    warn "  expected: $MAGISK_SIGNER_SHA256"
    warn "  got     : $signer"
    ok=0
  fi

  [[ "$ok" -eq 1 ]]
}

# Download the Magisk APK from the OFFICIAL GitHub releases (latest, or the
# given tag) into $WORK, verify it, and echo its path. Fails closed.
fetch_and_verify_magisk() {
  local tag="$1"
  command -v curl >/dev/null 2>&1 || die "curl not on PATH (needed for --fetch-magisk)"

  if [[ -z "$tag" ]]; then
    note "resolving latest Magisk release tag ..."
    tag="$(curl -fsSL "https://api.github.com/repos/$MAGISK_REPO/releases/latest" 2>/dev/null \
      | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
    [[ -n "$tag" ]] || die "could not resolve latest Magisk tag (network / API issue) - pass --fetch-magisk=vX.Y.Z"
  fi

  local url="https://github.com/$MAGISK_REPO/releases/download/$tag/Magisk-$tag.apk"
  local out="$WORK/Magisk-$tag.apk"
  note "downloading $url ..."
  curl -fsSL -o "$out" "$url" || die "download failed for tag $tag (does the release exist?)"
  [[ -s "$out" ]] || die "downloaded APK is empty: $out"

  verify_apk "$out" || die "fetched APK failed verification - refusing to use it"
  note "verified Magisk $tag."
  printf '%s\n' "$out"
}

# Factory-image lookup (Google Flash Tool API). Google's old factory-images HTML
# page is now client-rendered (no URLs/hashes
# in the served HTML), so we use the same backend the Android Flash Tool uses:
# scrape the public API key from flash.android.com, then query the builds API.
# This returns the real factoryImageDownloadUrl for ANY Pixel codename. The API
# does not publish a full SHA-256, but the download URL embeds the first 8 hex
# of the zip's SHA-256 (…-factory-<sha256[:8]>.zip), which we verify locally.

# Scrape the (public, client-side) Flash Tool API key, cached in $WORK.
_flash_api_key() {
  local cache="$WORK/flash_api_key"
  if [[ ! -s "$cache" ]]; then
    local html="$WORK/flash.html"
    curl -fsSL -A "$FLASH_UA" "$FLASH_URL" -o "$html" 2>/dev/null \
      || die "could not fetch $FLASH_URL (network issue?)"
    # The key is embedded in body[data-client-config] as &quot;AIza...&quot;.
    local key
    key="$(grep -oE 'AIzaSy[A-Za-z0-9_-]{33}' "$html" | head -1)"
    [[ -n "$key" ]] || die "could not extract the Flash Tool API key from $FLASH_URL (page layout changed?)"
    printf '%s' "$key" > "$cache"
  fi
  cat "$cache"
}

# Given a device codename and (optional) build id, resolve the factory-image zip
# URL and the SHA-256 PREFIX (first 8 hex) embedded in its filename. Echoes
# "URL<TAB>SHA256PREFIX". With no build id, picks the newest build for the device.
# Exit codes: 3 = device not found / no builds, 4 = requested build not found.
_resolve_factory_url() {
  local device="$1" build="$2" key json
  key="$(_flash_api_key)" || return 1
  json="$WORK/builds_${device}.json"
  if [[ ! -s "$json" ]]; then
    note "querying Flash Tool builds API for $device ..." >&2
    curl -fsSL -H "referer: $FLASH_URL" \
      "${FLASH_API}?key=${key}&product=${device}" -o "$json" 2>/dev/null \
      || die "Flash Tool builds API request failed for '$device' (network issue?)"
  fi
  python3 - "$json" "$device" "$build" <<'PY'
import json, re, sys
path, device, build = sys.argv[1], sys.argv[2], sys.argv[3].lower()
try:
    data = json.load(open(path, encoding="utf-8"))
except Exception:
    sys.exit(3)
builds = [b for b in data.get("flashstationBuild", []) if b.get("product") == device]
if not builds:
    sys.exit(3)  # device not found / API returned nothing for it
builds.sort(key=lambda b: int(b.get("buildId", "0")))

def sha8(url):
    # Google embeds the first 8 hex of the zip's SHA-256 in the filename.
    m = re.search(r'-factory-([0-9a-f]{8})\.zip$', url)
    return m.group(1) if m else ""

if build:
    for b in builds:
        rc = (b.get("releaseCandidateName") or "").lower()
        url = b.get("factoryImageDownloadUrl", "")
        # match either the release-candidate name (cp2a.260705.006) or the
        # exact build id substring in the URL.
        if rc == build or ("-%s-" % build) in url.lower():
            print(url + "\t" + sha8(url)); sys.exit(0)
    sys.exit(4)  # requested build not found for this device
# newest = highest buildId (prefer the one flagged latest if present)
latest = [b for b in builds if b.get("releaseBuildMetadata", {}).get("latest")]
chosen = latest[-1] if latest else builds[-1]
url = chosen.get("factoryImageDownloadUrl", "")
print(url + "\t" + sha8(url))
PY
}

# Verify that a file's SHA-256 begins with the given 8-hex prefix (the value
# Google embeds in the factory-zip filename). Returns 0 on match. Pass a 3rd arg
# "quiet" to suppress the success note (used for the cache probe). Fails (1) on
# mismatch or if the prefix is empty.
_verify_sha8() {
  local file="$1" want="$2" quiet="${3:-}"
  [[ -n "$want" ]] || return 1
  local full got
  full="$(shasum -a 256 "$file" 2>/dev/null | awk '{print $1}')"
  [[ -z "$full" ]] && full="$(sha256sum "$file" 2>/dev/null | awk '{print $1}')"
  got="$(printf '%s' "$full" | cut -c1-8 | tr '[:upper:]' '[:lower:]')"
  want="$(printf '%s' "$want" | tr '[:upper:]' '[:lower:]')"
  [[ -n "$got" && "$got" == "$want" ]] || return 1
  [[ "$quiet" == "quiet" ]] || note "factory image sha256 prefix OK ($full)" >&2
  return 0
}

# Resolve + download + SHA-256-prefix-verify the full factory zip for a device.
# Echoes the path to the verified zip in $WORK. Fails closed. Shared by
# --fetch-image (extract one partition) and --recover (run flash-all).
# (Google's Flash Tool API has no full SHA-256; the URL embeds the first 8 hex
# of the zip's SHA-256, which we verify against the download.)
_download_verify_factory_zip() {
  local device="$1" build="$2"
  command -v curl    >/dev/null 2>&1 || die "curl not on PATH (needed to fetch the factory image)"
  command -v python3 >/dev/null 2>&1 || die "python3 not on PATH (needed for the factory-image lookup)"
  [[ -n "$device" ]] || die "cannot fetch factory image: device codename unknown (is the device connected?)"

  local line url sha8
  note "resolving factory image for $device${build:+ (build $build)} ..." >&2
  line="$(_resolve_factory_url "$device" "$build")" || {
    case "$?" in
      3) die "device '$device' not found via the Flash Tool builds API (unknown codename, or the API returned nothing for it)" ;;
      4) die "build '$build' not found for '$device' via the Flash Tool API. It may be too new/old or a beta not exposed here. Options: omit the build to take the latest, pin a listed build (--fetch-image=<build-id> / --recover=<build-id>), or supply the image yourself with --image." ;;
      *) die "factory-image lookup failed for '$device'" ;;
    esac
  }
  url="${line%%$'\t'*}"; sha8="${line##*$'\t'}"
  [[ -n "$url" ]] || die "could not parse factory-image URL for '$device'"

  # Reuse an already-downloaded copy when caching is on (--keep-downloads). If a
  # prior run left the same-named zip in the cache and its SHA-256 prefix still
  # verifies, skip the multi-GB re-download entirely. Otherwise download into the
  # cache dir with resume (curl -C -), so an interrupted run continues instead of
  # starting over.
  local zip
  if [[ -n "$CACHE_DIR" ]]; then
    mkdir -p "$CACHE_DIR" 2>/dev/null || true
    zip="$CACHE_DIR/$(basename "$url")"
    if [[ -s "$zip" ]] && _verify_sha8 "$zip" "$sha8" quiet; then
      note "reusing cached factory image (sha256 prefix OK): $zip" >&2
      printf '%s\n' "$zip"
      return 0
    fi
    note "downloading factory image (cached, resumable): $url" >&2
    curl -fsSL -C - -A "$FLASH_UA" -o "$zip" "$url" \
      || die "factory image download failed: $url"
  else
    zip="$WORK/$(basename "$url")"
    note "downloading factory image: $url" >&2
    curl -fsSL -A "$FLASH_UA" -o "$zip" "$url" \
      || die "factory image download failed: $url"
  fi
  [[ -s "$zip" ]] || die "downloaded factory image is empty"

  # Integrity: Google embeds the FIRST 8 HEX OF THE ZIP'S SHA-256 in the
  # filename (…-factory-<sha256[:8]>.zip). Verify the download's SHA-256 begins
  # with it. This is a 32-bit prefix check - strong against corruption/truncation
  # and a solid tamper tripwire, though not the full 256-bit hash. Fail closed on
  # mismatch; warn (don't proceed silently) if the filename carried no prefix.
  if [[ -n "$sha8" ]]; then
    _verify_sha8 "$zip" "$sha8" \
      || die "factory image sha256-prefix MISMATCH for $(basename "$zip") - refusing to use it"
  else
    warn "factory image URL carried no sha256 prefix to verify against ('$(basename "$url")'); proceeding on the HTTPS download from dl.google.com." >&2
  fi
  printf '%s\n' "$zip"
}

# Full factory-image pipeline: resolve -> download -> verify SHA-256 -> unzip ->
# extract the root partition image. $part is the BEST GUESS (init_boot|boot);
# if the image doesn't contain it we fall back to the other, so the true
# partition is auto-detected from the factory package itself. Echoes the path to
# the extracted .img (named init_boot.img or boot.img - the caller re-derives
# the authoritative partition from that basename). Fails closed.
fetch_and_extract_image() {
  local device="$1" part="$2" build="$3"
  # No usable guess? Default to init_boot (every GKI-2.0 device); the fallback
  # below still finds `boot` for legacy Pixel-6-era images.
  [[ -n "$part" ]] || part="init_boot"

  local zip
  zip="$(_download_verify_factory_zip "$device" "$build")" \
    || die "factory-image download/verify failed for '$device' (see the error above)"
  # A `die` inside the command-substitution above only kills that subshell, so
  # guard against an empty/missing result before we try to use it.
  [[ -n "$zip" && -f "$zip" ]] || die "factory image was not produced for '$device' (download/verify aborted above)"

  # Factory zip contains a nested image-<device>-<build>.zip which holds the
  # partition images. Extract only that, then pull the one partition we need.
  local ex="$WORK/factory"; mkdir -p "$ex"
  unzip -o -q "$zip" -d "$ex" || die "could not unzip factory package"
  local nested
  nested="$(ls "$ex"/*/image-*.zip 2>/dev/null | head -1)"
  [[ -z "$nested" ]] && nested="$(ls "$ex"/image-*.zip 2>/dev/null | head -1)"
  [[ -n "$nested" ]] || die "nested image-*.zip not found inside factory package"

  # Which partition images does this factory package actually contain? Pick the
  # guess if present, else the other one - this self-corrects a wrong guess and
  # transparently handles any Pixel (6 => boot, 7/8/9/10/11+ => init_boot).
  local have
  have="$(unzip -Z1 "$nested" 2>/dev/null | grep -E '^(init_boot|boot)\.img$' | sed 's/\.img$//')"
  local chosen=""
  if printf '%s\n' "$have" | grep -qx "$part"; then
    chosen="$part"
  elif printf '%s\n' "$have" | grep -qx "init_boot"; then
    chosen="init_boot"
  elif printf '%s\n' "$have" | grep -qx "boot"; then
    chosen="boot"
  fi
  [[ -n "$chosen" ]] || die "neither init_boot.img nor boot.img found in $nested - unsupported factory package for '$device'"
  if [[ "$chosen" != "$part" ]]; then
    warn "guessed '$part' but this factory image provides '$chosen' - using '$chosen' (auto-corrected for $device)." >&2
  fi

  note "extracting $chosen.img from factory package ..." >&2
  unzip -o -q "$nested" -d "$ex/img" "$chosen.img" || die "$chosen.img not found in $nested"
  local img="$ex/img/$chosen.img"
  [[ -f "$img" ]] || die "expected $img after extraction"
  note "extracted $(basename "$img") ($(wc -c < "$img") bytes)" >&2
  printf '%s\n' "$img"
}

# Full brick recovery: re-download + SHA-256-verify the full factory zip, unzip
# it, and run its bundled flash-all script to restore EVERY partition to stock.
# DESTRUCTIVE (wipes user data + rewrites both A/B slots). Typed confirm unless
# --yes. Its own mode: does NOT patch or install Magisk. Fails closed.
recover_from_factory() {
  local device="$1" build="$2"
  [[ -n "$device" ]] || die "cannot recover: device codename unknown (is it connected / in fastboot?)"

  if [[ "$ASSUME_YES" -ne 1 ]]; then
    warn "About to FACTORY-RESTORE this device (flash-all):"
    warn "    device : $device"
    warn "    build  : ${build:-<newest listed>}"
    warn "This ERASES all user data and rewrites bootloader/radio + both slots."
    warn "It is safe ONLY on an unlocked TEST device."
    printf '\033[1;33m[root_pixel]\033[0m Type exactly RECOVER to proceed: ' >&2
    read -r reply
    [[ "$reply" == "RECOVER" ]] || die "confirmation not received (got '${reply:-}'); aborting without writing."
  else
    warn "--yes given: factory-restoring $device unattended (no prompt)."
  fi

  local zip
  zip="$(_download_verify_factory_zip "$device" "$build")" \
    || die "factory-image download/verify failed for '$device' (see the error above)"
  [[ -n "$zip" && -f "$zip" ]] || die "factory image was not produced for '$device' (download/verify aborted above)"

  local ex="$WORK/recover"; mkdir -p "$ex"
  note "unpacking factory package for flash-all ..."
  unzip -o -q "$zip" -d "$ex" || die "could not unzip factory package"
  # flash-all(.sh) lives in the top-level <device>-<build>/ dir inside the zip.
  local fa
  fa="$(ls "$ex"/*/flash-all.sh 2>/dev/null | head -1)"
  [[ -z "$fa" ]] && fa="$(ls "$ex"/flash-all.sh 2>/dev/null | head -1)"
  [[ -n "$fa" ]] || die "flash-all.sh not found inside the factory package"
  chmod +x "$fa" 2>/dev/null || true

  # flash-all reboots to the bootloader itself, but do it here too so a booted
  # (non-bricked) device is in the right mode and we surface unlock problems.
  note "entering bootloader for flash-all ..."
  enter_fastboot
  assert_fastboot_unlocked

  note "running $(basename "$fa") (this takes several minutes; do not disconnect) ..."
  ( cd "$(dirname "$fa")" && ./flash-all.sh ) \
    || die "flash-all failed - device left in bootloader; re-run --recover or use the Android Flash Tool (https://flash.android.com/). Do NOT leave it half-flashed."

  note "flash-all finished; waiting for Android to come back ..."
  wait_for_boot 300
  note "RECOVERY COMPLETE - $device restored to stock build ${build:-<newest listed>}. Re-root from the Root-with-Magisk guide if desired."
}

# Device-state helpers (robust waits for the flaky adb<->fastboot hops).
# Wait up to N seconds for the device to enumerate in fastboot mode.
wait_for_fastboot() {
  local secs="${1:-60}" i=0
  while [[ "$i" -lt "$secs" ]]; do
    fastboot devices 2>/dev/null | grep -q . && return 0
    sleep 1; i=$((i+1))
  done
  return 1
}

# Reboot to the bootloader from whatever state we're in, then wait for fastboot.
enter_fastboot() {
  if fastboot devices 2>/dev/null | grep -q .; then return 0; fi
  if adb get-state >/dev/null 2>&1; then
    adb reboot bootloader >/dev/null 2>&1 || true
  fi
  wait_for_fastboot 60 || die "device did not enter fastboot mode (check cable/hub, or bootloader confirm on-screen)"
}

# Wait (bounded) for Android to come back AND finish booting. Bare
# `adb wait-for-device` blocks forever if the device never re-enumerates and
# returns the instant adbd answers (often still mid-boot), so we cap the
# enumeration wait and then poll sys.boot_completed.
wait_for_boot() {
  local secs="${1:-180}" i=0
  # 1) bounded wait for adb to re-enumerate (run in background so we can time it)
  adb wait-for-device &
  local wf=$!
  while kill -0 "$wf" 2>/dev/null; do
    [[ "$i" -ge "$secs" ]] && { kill "$wf" 2>/dev/null; die "timed out after ${secs}s waiting for the device to re-appear on adb (bad cable/port, boot hang, or an on-screen prompt?)"; }
    sleep 1; i=$((i+1))
  done
  wait "$wf" 2>/dev/null || true
  # 2) bounded wait for the OS to report boot completion
  while [[ "$i" -lt "$secs" ]]; do
    [[ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]] && return 0
    sleep 2; i=$((i+2))
  done
  warn "device is on adb but sys.boot_completed!=1 after ${secs}s; continuing anyway."
  return 0
}

# Return 0 if `su -c id` reports uid=0. Retries a few times: Magisk's daemon can
# take a moment after first boot.
# Return 0 if a root shell reports uid=0. Magisk's `su` lives on its own mount
# (e.g. /debug_ramdisk/su) that isn't on the adb shell PATH, so we try both the
# bare name and known absolute paths. Retries a few times: magiskd can take a
# moment after first boot, and a freshly-granted policy may need a beat.
check_root() {
  local i=0
  while [[ "$i" -lt 6 ]]; do
    adb shell 'for s in su /debug_ramdisk/su /sbin/su /system/bin/su; do \
      command -v "$s" >/dev/null 2>&1 || [ -x "$s" ] || continue; \
      "$s" -c id 2>/dev/null | grep -q "uid=0" && exit 0; \
    done; exit 1' 2>/dev/null && return 0
    sleep 3; i=$((i+1))
  done
  return 1
}

# Path to Magisk's su as seen on-device (set by check_root style probing). We
# resolve it once so grant-persistence can shell out to `magisk --sqlite`.
resolve_su_path() {
  adb shell 'for s in su /debug_ramdisk/su /sbin/su /system/bin/su; do \
    { command -v "$s" >/dev/null 2>&1 || [ -x "$s" ]; } && { echo "$s"; break; }; \
  done' 2>/dev/null | tr -d '\r'
}

# Once the shell (UID 2000 / com.android.shell) has been granted su ONCE via the
# Magisk app, make it permanent and non-interactive: set global root_access=3
# (Apps and ADB) and pin an allow policy for UID 2000. Runs *through* the granted
# su, so it only works after the one-time in-app enablement. Best-effort.
persist_shell_grant() {
  local su; su="$(resolve_su_path)"
  [[ -n "$su" ]] || return 1
  adb shell "$su -c 'magisk --sqlite \"REPLACE INTO settings (key,value) VALUES(\\\"root_access\\\",3)\"; magisk --sqlite \"REPLACE INTO policies (uid,policy,until,logging,notification) VALUES(2000,2,0,0,0)\"'" >/dev/null 2>&1 \
    && return 0
  return 1
}

# UI-automation helpers (best-effort; used only by --auto-finalize). Magisk
# exposes no CLI for its first-run enablement, so the only way to make it
# hands-free is to drive the app UI. To stay robust across Magisk versions and
# device languages we locate controls by STRUCTURE, never by pixel position or
# translated text:
#   • resource-id (com.topjohnwu.magisk:id/…) - the app's own stable view ids;
#   • non-localized identifiers - e.g. the package name "com.android.shell",
#     which is identical on every device and in every locale.
# Every step degrades gracefully; the caller always has a printed manual fallback.
UI_XML="/sdcard/dvma_ui.xml"

# Dump the current view hierarchy to a local file. 0 on success.
ui_dump() {
  local out="$1"
  adb shell uiautomator dump "$UI_XML" >/dev/null 2>&1 || return 1
  adb pull "$UI_XML" "$out" >/dev/null 2>&1 || return 1
  [[ -s "$out" ]] || return 1
  return 0
}

# Print "x y" (tap center) of the FIRST node matching an extended-regex over its
# serialized attributes. Empty if not found. Prefer resource-ids / stable ids.
ui_center_of() {
  local xml="$1" re="$2"
  tr '<' '\n' < "$xml" \
    | grep -E "$re" | head -1 \
    | grep -oE 'bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"' | head -1 \
    | grep -oE '[0-9]+' \
    | { read -r x1 && read -r y1 && read -r x2 && read -r y2 \
        && printf '%d %d\n' $(( (x1 + x2) / 2 )) $(( (y1 + y2) / 2 )); }
}

# Locate the su switch for a policy row identified by a STABLE anchor (default:
# the non-localized package name "com.android.shell"). Strategy: find the anchor
# text node's vertical center, then pick the Switch whose center is closest to
# that same row (nearest vertical center, within a tolerance). This tolerates
# sibling layout (the Switch and the package-name TextView are peers, so their
# exact bounds don't nest), multiple policies, reordering, and translated UI.
# Prints "checked x y" (checked ∈ true/false), or empty if no anchor row.
# $1 = dumped xml path, $2 = anchor regex (optional).
ui_shell_switch() {
  local xml="$1" anchor="${2:-com\.android\.shell}"
  awk -v anchor="$anchor" '
    function bounds(s) {
      if (match(s, /bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"/)) {
        b = substr(s, RSTART, RLENGTH)
        gsub(/[^0-9,]/, " ", b)
        n = 0; split(b, a, /[ ,]+/)
        for (i in a) if (a[i] != "") { n++; v[n] = a[i] }
        X1 = v[1]; Y1 = v[2]; X2 = v[3]; Y2 = v[4]
        return (n >= 4)
      }
      return 0
    }
    BEGIN { RS = "<"; acy = -1 }
    {
      node = $0
      # Anchor: remember the vertical center of the package-name text node.
      if (node ~ anchor && bounds(node)) {
        c = int((Y1 + Y2) / 2)
        if (acy < 0) acy = c            # first (topmost) match wins
      }
      # Collect every Switch with its center + checked state.
      if (node ~ /class="android\.widget\.Switch"/ && bounds(node)) {
        sw_cy[++sc] = int((Y1 + Y2) / 2)
        sw_cx[sc]   = int((X1 + X2) / 2)
        sw_chk[sc]  = (node ~ /checked="true"/) ? "true" : "false"
      }
    }
    END {
      if (acy < 0 || sc == 0) exit 0    # no anchor or no switches
      best = -1; bestd = 999999999
      for (i = 1; i <= sc; i++) {
        d = sw_cy[i] - acy; if (d < 0) d = -d
        if (d < bestd) { bestd = d; best = i }
      }
      # Guard: the matched switch must plausibly be on the same row (row heights
      # are ~150px; allow generous 200px so we never grab a far-away control).
      if (best > 0 && bestd <= 200) print sw_chk[best], sw_cx[best], sw_cy[best]
    }
  ' "$xml"
}

# Best-effort UI drive of Magisk's one-time enablement, mirroring the exact steps
# that work by hand: (1) if the "additional setup" dialog is up, tap its positive
# button and wait for the auto-reboot; (2) open the Superuser tab; (3) flip the
# shell (com.android.shell) policy switch ON, located structurally; (4) confirm
# su, then persist. Returns 0 only if the shell ends up with uid=0. Never fatal.
auto_finalize_magisk() {
  local tmp; tmp="$(mktemp)" || return 1
  # shellcheck disable=SC2064
  trap "rm -f '$tmp'" RETURN

  note "auto-finalize: driving Magisk's one-time setup via UI (structure-based) ..."

  # 1) "additional setup" dialog -> tap its positive button (found by the app's
  #    own button id, not by the word "OK"), then it reboots itself.
  if ui_dump "$tmp" && grep -qiE 'additional setup|dialog_base_button_1' "$tmp"; then
    local ok; ok="$(ui_center_of "$tmp" 'resource-id="com\.topjohnwu\.magisk:id/dialog_base_button_1"')"
    if [[ -n "$ok" ]]; then
      note "auto-finalize: confirming Magisk 'additional setup' (reboots itself) ..."
      adb shell input tap $ok >/dev/null 2>&1
      sleep 3; adb wait-for-device >/dev/null 2>&1; wait_for_boot 180
    fi
  fi

  # If setup alone already yielded root (some devices), we're done.
  check_root && { persist_shell_grant && note "auto-finalize: root active + persisted."; return 0; }

  # 2) Open the app and switch to the Superuser tab (by its fragment id).
  adb shell 'am start -n com.topjohnwu.magisk/.ui.MainActivity' >/dev/null 2>&1 || true
  sleep 2
  ui_dump "$tmp" || { warn "auto-finalize: could not read the Magisk UI."; return 1; }
  local su_tab; su_tab="$(ui_center_of "$tmp" 'resource-id="com\.topjohnwu\.magisk:id/superuserFragment"')"
  [[ -n "$su_tab" ]] && { adb shell input tap $su_tab >/dev/null 2>&1; sleep 2; }

  # 3) Find the shell policy row's Switch structurally and turn it ON if OFF.
  ui_dump "$tmp" || { warn "auto-finalize: could not read the Superuser list."; return 1; }
  if ! grep -qi 'com.android.shell' "$tmp"; then
    # No shell policy yet: poke su once to register the row, then re-dump.
    adb shell '/debug_ramdisk/su -c id' >/dev/null 2>&1 || true
    sleep 2; ui_dump "$tmp" || true
  fi
  local row; row="$(ui_shell_switch "$tmp")"       # "checked x y" or empty
  if [[ -n "$row" ]]; then
    local chk cx cy; read -r chk cx cy <<<"$row"
    if [[ "$chk" == "false" && -n "$cx" && -n "$cy" ]]; then
      note "auto-finalize: enabling root for the ADB shell (com.android.shell) ..."
      adb shell input tap "$cx" "$cy" >/dev/null 2>&1; sleep 2
    elif [[ "$chk" == "true" ]]; then
      note "auto-finalize: shell su switch already ON."
    fi
  else
    warn "auto-finalize: couldn't locate the shell policy row (layout changed?)."
  fi

  # 4) Verify + persist.
  if check_root; then
    persist_shell_grant \
      && note "auto-finalize: root granted to the shell and persisted (future runs are zero-touch)." \
      || warn "auto-finalize: root works now but persisting the policy failed; it may re-prompt."
    return 0
  fi
  warn "auto-finalize: UI steps ran but the shell still isn't root (Magisk layout may have changed)."
  return 1
}

# After a patched boot image is live, root is INSTALLED (magiskd runs), but
# MagiskSU still gates the very first `su` request from the adb shell: with an
# unconfigured manager Magisk *silently rejects* it - it renders NO dialog, so
# there is nothing to `adb input tap`. Enabling it is a one-time in-app action:
# open Magisk → Settings → "Superuser access: Apps and ADB". We (1) install the
# full app so there's no "download full Magisk" detour, (2) open the app to that
# setting, (3) poll until the shell is granted, then (4) persist the grant so all
# future runs are zero-touch. topjohnwu ships no CLI to pre-authorize the first
# grant (only offline magisk.db seeding from recovery can), so this single toggle
# is the sole unavoidable interaction. We say so plainly.
# $1 = path to the (already verified) full Magisk APK.
finalize_magisk() {
  local apk="$1"
  if [[ -f "$apk" ]]; then
    note "installing the FULL Magisk app (skips the 'download full Magisk' prompt) ..."
    adb install -r "$apk" >/dev/null 2>&1 && note "full Magisk app installed." \
      || warn "adb install of the full app failed; the stub may offer to download it (needs network + a tap)."
  else
    warn "finalize: full Magisk APK not found ($apk); skipping app install."
  fi

  # If root already works (e.g. a previous run persisted the grant), we're done.
  if check_root; then
    note "root already granted to the shell - nothing to do."
    return 0
  fi

  # --auto-finalize: try to drive the two one-time taps via UI automation. This
  # is best-effort and version-fragile; if it can't, we fall through to the
  # manual guidance + poll below.
  if [[ "$AUTO_FINALIZE" -eq 1 ]]; then
    if auto_finalize_magisk; then
      return 0
    fi
    warn "auto-finalize did not complete; falling back to guided manual steps."
  fi

  # Open Magisk to the Superuser settings so the toggle is one tap away.
  adb shell 'am start -n com.topjohnwu.magisk/.ui.MainActivity >/dev/null 2>&1 || \
             am start com.topjohnwu.magisk >/dev/null 2>&1' >/dev/null 2>&1 || true

  cat >&2 <<'EOF'
[root_pixel] ONE-TIME manual step (Magisk's security boundary):
[root_pixel]   Magisk gates the shell's su until you enable it in-app once:
[root_pixel]     1. If "Requires additional setup" shows, tap OK (it reboots).
[root_pixel]     2. Open Magisk -> Superuser tab -> turn ON the switch for
[root_pixel]        "[SharedUID] Shell" (com.android.shell).
[root_pixel]   (Tip: --auto-finalize attempts both taps for you automatically.)
[root_pixel] Waiting up to 120s for the shell to be granted root ...
EOF

  # Poll: repeatedly poke su (surfaces the request once the setting is on) and
  # check for uid=0. Once granted, lock it in so we never ask again.
  local waited=0
  while [[ "$waited" -lt 120 ]]; do
    adb shell 'for s in su /debug_ramdisk/su /sbin/su /system/bin/su; do \
      { command -v "$s" >/dev/null 2>&1 || [ -x "$s" ]; } && "$s" -c id >/dev/null 2>&1 && break; \
    done' >/dev/null 2>&1
    if check_root; then
      note "shell granted root."
      if persist_shell_grant; then
        note "persisted: Superuser access = Apps and ADB, UID 2000 allowed. Future runs are zero-touch."
      else
        warn "could not persist the grant automatically; it may re-prompt next boot."
      fi
      return 0
    fi
    sleep 5; waited=$((waited+5))
  done

  warn "no root grant detected within 120s. Enable 'Superuser access: Apps and ADB'"
  warn "in the Magisk app, then verify: adb shell su -c id   # expect uid=0"
  return 1
}

# Resolve exactly one usable adb device and set $SERIAL to it. Distinguishes
# absent / unauthorized / offline, refuses ambiguity when >1 device is present
# (unless --serial picked one), and fails closed with an actionable message.
select_device() {
  # `adb devices` lines after the header are: "<serial>\t<state>".
  local lines
  lines="$(command adb devices 2>/dev/null | sed '1d' | sed '/^\s*$/d')"

  if [[ -z "$lines" ]]; then
    die "no device detected by adb. Check: USB cable/port, that the device is on, and that 'USB debugging' is enabled (Settings > Developer options). If adb was just started, re-run."
  fi

  # Surface non-ready states explicitly - they're the usual real-world snags.
  local unauth offline
  unauth="$(printf '%s\n' "$lines" | awk '$2=="unauthorized"{print $1}')"
  offline="$(printf '%s\n' "$lines" | awk '$2=="offline"{print $1}')"
  if [[ -n "$unauth" ]]; then
    warn "device(s) UNAUTHORIZED for adb: $unauth"
    warn "  -> unlock the device screen and tap 'Allow' on the 'Allow USB debugging?'"
    warn "     prompt (tick 'Always allow from this computer'). Then re-run."
  fi
  [[ -n "$offline" ]] && warn "device(s) OFFLINE: $offline (try re-plugging or 'adb kill-server')."

  # Only 'device' state is usable for our work.
  local ready
  ready="$(printf '%s\n' "$lines" | awk '$2=="device"{print $1}')"

  # If the caller pinned --serial, validate it against ready devices.
  if [[ -n "$SERIAL" ]]; then
    if printf '%s\n' "$ready" | grep -qx "$SERIAL"; then
      note "using --serial $SERIAL"
      return 0
    fi
    warn "ready devices are:"
    if [[ -n "$ready" ]]; then printf '%s\n' "$ready" | sed 's/^/    /' >&2; else warn "    (none)"; fi
    die "--serial '$SERIAL' is not a ready adb device (unauthorized/offline devices don't count)."
  fi

  local count
  count="$(printf '%s\n' "$ready" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [[ "$count" -eq 0 ]]; then
    die "a device is connected but none are in the 'device' (ready) state - see the authorization/offline notes above."
  fi
  if [[ "$count" -gt 1 ]]; then
    warn "more than one ready device is connected:"
    printf '%s\n' "$ready" | sed 's/^/    /' >&2
    die "refusing to guess which device to root. Re-run with --serial <one-of-the-above>."
  fi
  SERIAL="$(printf '%s\n' "$ready" | sed '/^$/d' | head -1)"
  note "auto-selected the only ready device: $SERIAL"
}

# For a DESTRUCTIVE flash, confirm the bootloader is actually unlocked. We probe
# via adb (getprop) when booted, and can confirm authoritatively in fastboot via
# `getvar unlocked`. Refuse to flash a locked device (flashing would just fail,
# often after a confusing partial state).
require_bootloader_unlocked() {
  # Cheap advisory read while still in Android.
  local p
  p="$(adb shell getprop ro.boot.flash.locked 2>/dev/null | tr -d '\r')"
  # ro.boot.flash.locked: 1 => locked, 0 => unlocked (Pixel).
  if [[ "$p" == "1" ]]; then
    die "bootloader appears LOCKED (ro.boot.flash.locked=1). Unlock it first (one-time, WIPES the device): enable 'OEM unlocking' in Developer options, then 'adb reboot bootloader && fastboot flashing unlock' and confirm on-screen with the volume/power keys. This CANNOT be scripted."
  fi
  # p=="0" (unlocked) or empty (prop absent) - we'll get the authoritative
  # answer from fastboot's `getvar unlocked` once we're in the bootloader.
}

# Authoritative unlock check in fastboot mode; call after enter_fastboot.
assert_fastboot_unlocked() {
  local u
  u="$(fastboot getvar unlocked 2>&1 | sed -n 's/^unlocked: *//p' | head -1 | tr -d '\r')"
  if [[ "$u" == "no" ]]; then
    die "bootloader is LOCKED (fastboot: unlocked=no). Run 'fastboot flashing unlock' (WIPES the device, needs on-screen confirmation) before flashing. Rebooting back to Android now would be safe; nothing was written."
  fi
  # "yes" => proceed; empty/unknown => can't tell, warn but continue (the flash
  # itself will fail closed if truly locked).
  [[ "$u" == "yes" ]] || warn "could not read bootloader unlock state (getvar unlocked='${u:-?}'); proceeding - flash will fail safely if locked."
}


APK=""
FETCH_MAGISK=0
FETCH_TAG=""          # empty => latest
EXPECT_SHA256=""
IMAGE=""
FETCH_IMAGE=0
FETCH_BUILD=""        # empty => detect from device
OUT="./magisk_patched.img"
ARCH="arm64-v8a"
BOOT_TEST=0
FLASH=0
AUTO_FINALIZE=0       # --auto-finalize: best-effort UI automation of the two
                      # one-time Magisk taps (setup dialog + Shell su toggle)
RECOVER=0
RECOVER_BUILD=""      # empty => newest listed for the device
ASSUME_YES=0
SERIAL=""
KEEP_DOWNLOADS=0
KEEP_DIR=""           # empty => ./dvma-downloads when --keep-downloads is set
CACHE_DIR=""          # persistent download store for reuse; set when caching is on
DEVICE_TMP="/data/local/tmp/dvma_mroot"

# The official Magisk release signer (CN=John Wu). A patched boot image grants
# root, so we verify the APK we extract the patcher from is signed by this exact
# key before trusting it. Long-lived cert (valid 2016..2116); update only if
# topjohnwu rotates the release key.
MAGISK_SIGNER_SHA256="B4:CB:83:B4:DA:D9:9F:99:7D:BE:87:2F:01:3A:A1:6C:14:EE:C4:1D:16:70:21:F3:71:F7:E1:33:0F:27:3E:E6"
MAGISK_REPO="topjohnwu/Magisk"

# Google Flash Tool backend. The old developers.google.com/android/images page
# is now client-rendered (no URLs/hashes in the HTML), so we use the same API
# the Android Flash Tool uses: scrape the public API key from flash.android.com,
# then query the builds endpoint for the device's factoryImageDownloadUrl. The
# URL embeds the first 8 hex of the zip's SHA-256 (…-factory-<sha256[:8]>.zip),
# which we verify locally.
FLASH_URL="https://flash.android.com/"
FLASH_API="https://content-flashstation-pa.googleapis.com/v1/builds"
# A desktop UA avoids the ES5 minified variant and keeps the key easy to find.
FLASH_UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"

usage() { sed -n '2,109p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apk)            APK="${2:?--apk needs a path}"; shift 2 ;;
    --fetch-magisk)   FETCH_MAGISK=1; shift ;;
    --fetch-magisk=*) FETCH_MAGISK=1; FETCH_TAG="${1#*=}"; shift ;;
    --sha256)         EXPECT_SHA256="${2:?--sha256 needs a hex digest}"; shift 2 ;;
    --image)          IMAGE="${2:?--image needs a path}"; shift 2 ;;
    --fetch-image)    FETCH_IMAGE=1; shift ;;
    --fetch-image=*)  FETCH_IMAGE=1; FETCH_BUILD="${1#*=}"; shift ;;
    --flash)          FLASH=1; shift ;;
    --auto-finalize)  AUTO_FINALIZE=1; shift ;;
    --recover)        RECOVER=1; shift ;;
    --recover=*)      RECOVER=1; RECOVER_BUILD="${1#*=}"; shift ;;
    --yes|-y)         ASSUME_YES=1; shift ;;
    --serial)         SERIAL="${2:?--serial needs a device serial}"; shift 2 ;;
    --keep-downloads) KEEP_DOWNLOADS=1; shift ;;
    --keep-downloads=*) KEEP_DOWNLOADS=1; KEEP_DIR="${1#*=}"; shift ;;
    --out)            OUT="${2:?--out needs a path}"; shift 2 ;;
    --arch)           ARCH="${2:?--arch needs an ABI}"; shift 2 ;;
    --boot-test)      BOOT_TEST=1; shift ;;
    -h|--help)        usage 0 ;;
    *)                die "unknown argument: $1 (see --help)" ;;
  esac
done

# Preflightcommand -v adb      >/dev/null 2>&1 ||
die "adb not on PATH (install Android platform-tools)"
command -v fastboot >/dev/null 2>&1 || die "fastboot not on PATH (install Android platform-tools)"
command -v unzip    >/dev/null 2>&1 || die "unzip not on PATH"
command -v curl     >/dev/null 2>&1 || die "curl not on PATH"

# Mutually-exclusive input pairs.
if [[ "$FETCH_MAGISK" -eq 1 && -n "$APK" ]]; then
  die "pass EITHER --apk OR --fetch-magisk, not both (see --help)"
fi
if [[ "$FETCH_IMAGE" -eq 1 && -n "$IMAGE" ]]; then
  die "pass EITHER --image OR --fetch-image, not both (see --help)"
fi
# --recover is its own standalone mode (factory-restore, no patch/flash). It
# doesn't combine with the rooting inputs.
if [[ "$RECOVER" -eq 1 ]]; then
  if [[ "$FETCH_MAGISK" -eq 1 || -n "$APK" || "$FETCH_IMAGE" -eq 1 || -n "$IMAGE" || "$FLASH" -eq 1 || "$BOOT_TEST" -eq 1 ]]; then
    die "--recover is a standalone factory-restore mode; don't combine it with --apk/--fetch-magisk/--image/--fetch-image/--flash/--boot-test (see --help)"
  fi
fi

# When --keep-downloads is set, use its dir as a PERSISTENT download cache so
# repeat runs reuse an already-verified factory zip (no multi-GB re-download)
# and resume interrupted transfers. Without --keep-downloads, downloads live in
# the ephemeral $WORK and are removed on exit.
if [[ "$KEEP_DOWNLOADS" -eq 1 ]]; then
  CACHE_DIR="${KEEP_DIR:-./dvma-downloads}"
fi

# Working dir (also used to hold fetched artifacts). Cleaned on exit - unless
# --keep-downloads is set, in which case the fetched Magisk APK / factory image
# are copied to the keep dir first.
WORK="$(mktemp -d)"
cleanup() {
  local rc=$?
  if [[ "$KEEP_DOWNLOADS" -eq 1 ]]; then
    local dest="${KEEP_DIR:-./dvma-downloads}"
    mkdir -p "$dest" 2>/dev/null || true
    # Copy just the fetched inputs (APK, factory zip, extracted partition img);
    # skip the scratch HTML index and the on-device staging copies. The
    # extracted .img sits at $WORK/factory/img/<part>.img (depth 3).
    find "$WORK" -maxdepth 3 -type f \
      \( -name '*.apk' -o -name '*-factory-*.zip' -o -name 'init_boot.img' -o -name 'boot.img' \) \
      -exec cp -f {} "$dest/" \; 2>/dev/null || true
    printf '\033[1;36m[root_pixel]\033[0m kept downloads in %s\n' "$dest" >&2
  fi
  rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT

# Recovery mode: factory-restore and exit (no patch/root pipeline)
if [[ "$RECOVER" -eq 1 ]]; then
  # Prefer a booted adb device for the codename; fall back to fastboot when the
  # device is bricked and only reachable in the bootloader.
  rdevice=""
  if command adb devices 2>/dev/null | sed '1d' | awk '$2=="device"{f=1} END{exit !f}'; then
    select_device
    rdevice="$(adb shell getprop ro.product.device 2>/dev/null | tr -d '\r')"
  elif command fastboot devices 2>/dev/null | grep -q .; then
    note "no booted adb device; found a device in fastboot - reading codename from the bootloader."
    rdevice="$(command fastboot getvar product 2>&1 | sed -n 's/^product: *//p' | head -1 | tr -d '\r')"
  else
    die "no device found on adb or fastboot. For a hard brick, put the device in bootloader/fastboot mode (hold Power+Vol-Down) and reconnect, then re-run --recover. If it can't reach fastboot at all, use the Android Flash Tool: https://flash.android.com/"
  fi
  [[ -n "$rdevice" ]] || die "could not determine the device codename for recovery (is it fully connected?)"
  recover_from_factory "$rdevice" "$RECOVER_BUILD"
  exit 0
fi

# APK source: EITHER --apk OR --fetch-magisk (verified), never both
if [[ "$FETCH_MAGISK" -eq 1 ]]; then
  APK="$(fetch_and_verify_magisk "$FETCH_TAG")"
fi
[[ -n "$APK"   ]] || die "missing Magisk APK: pass --apk PATH or --fetch-magisk; see --help"
[[ -f "$APK"   ]] || die "APK not found: $APK"
# A supplied (--apk) file is verified too when the operator pins --sha256 and/or
# a signer-check tool is available; a fetched file was already verified above.
if [[ "$FETCH_MAGISK" -eq 0 ]]; then
  verify_apk "$APK" || die "supplied APK failed verification (see above)"
fi

# Resolve exactly one ready device (handles none / unauthorized / offline /
# multiple), pinning $SERIAL so every adb/fastboot call targets it.
select_device

DEVICE="$(adb shell getprop ro.product.device 2>/dev/null | tr -d '\r')"
# Factory-image URLs key off ro.build.id (e.g. "cp3a.260905.009"), NOT the bare
# numeric ro.build.version.incremental - so match on ro.build.id.
BUILD_ID="$(adb shell getprop ro.build.id 2>/dev/null | tr -d '\r')"
note "target device: ${DEVICE:-unknown} ($SERIAL) / build $(adb shell getprop ro.build.fingerprint 2>/dev/null | tr -d '\r')"
warn "reminder: patch the image FOR THIS device; the bootloader must already be unlocked to flash later."

# For a destructive flash, verify unlock state up-front (advisory read now, and
# an authoritative fastboot check just before writing).
if [[ "$FLASH" -eq 1 ]]; then
  require_bootloader_unlocked
fi

# Map the connected device to the partition Magisk root lives in. The rule is
# LAUNCH Android version, not model number: devices that launched on Android 12
# or earlier use the legacy `boot` ramdisk; everything that launched on Android
# 13+ (GKI 2.0) uses `init_boot`. For Pixels that means ONLY the Pixel 6 family
# (bluejay/oriole/raven, Tensor G1, launched A12) is `boot`; Pixel 7/8/9/10/11
# and up are all `init_boot`. Rather than pin an ever-growing codename list
# (which goes stale each new Pixel), we hardcode just the Pixel-6 exceptions and
# DEFAULT to init_boot - then verify against the actual factory image below, so
# a wrong guess can never cause a bad flash.
case "$DEVICE" in
  bluejay|oriole|raven)  PART="boot" ;;      # Pixel 6a / 6 / 6 Pro (Tensor G1, legacy GKI)
  "")                    PART="" ;;          # device codename unknown
  *)                     PART="init_boot" ;; # Pixel 7/8/9/10/11+ and any newer GKI-2.0 device
esac

# Image source: EITHER --image OR --fetch-image (auto from Google)
if [[ "$FETCH_IMAGE" -eq 1 ]]; then
  # Prefer an explicitly pinned build; else the device's current build, so the
  # patched partition matches what's actually installed (avoids version skew).
  IMG_BUILD="$FETCH_BUILD"
  if [[ -z "$IMG_BUILD" && -n "$BUILD_ID" ]]; then
    IMG_BUILD="$(printf '%s' "$BUILD_ID" | tr '[:upper:]' '[:lower:]')"
    note "no --fetch-image build pinned; matching the device's current build id: $IMG_BUILD"
  fi
  IMAGE="$(fetch_and_extract_image "$DEVICE" "$PART" "$IMG_BUILD")"
  # The extractor auto-detects the true partition and names the file after it
  # (init_boot.img | boot.img). Re-derive PART from that so we flash the right
  # one even for a device whose codename we didn't recognise.
  case "$(basename "$IMAGE")" in
    init_boot.img) PART="init_boot" ;;
    boot.img)      PART="boot" ;;
  esac
fi
[[ -n "$IMAGE" ]] || die "missing image: pass --image PATH or --fetch-image; see --help"
[[ -f "$IMAGE" ]] || die "boot image not found: $IMAGE"

# Sanity-check the supplied/fetched image against the device's root partition -
# flashing an init_boot image to `boot` (or vice-versa) is the #1 cause of a
# post-flash bootloop. With --fetch-image PART is now authoritative (derived
# from the extracted file). For a manually-supplied --image on an unrecognised
# device, infer PART from the filename so --flash still knows where to write.
if [[ -z "$PART" ]]; then
  case "$(basename "$IMAGE")" in
    *init_boot*) PART="init_boot"; note "inferred root partition 'init_boot' from image filename." ;;
    *boot*)      PART="boot";      note "inferred root partition 'boot' from image filename." ;;
  esac
fi
if [[ -n "$PART" ]]; then
  note "this device roots via the '$PART' partition - the patched image targets it."
  case "$(basename "$IMAGE")" in
    *"$PART"*) : ;;
    *) warn "image '$(basename "$IMAGE")' does not look like a '$PART' image for $DEVICE - double-check you extracted the right partition." ;;
  esac
elif [[ "$FLASH" -eq 1 ]]; then
  die "cannot determine the root partition for '$DEVICE' from the image name - refusing to --flash. Rename the image to init_boot.img/boot.img, or flash manually (see final instructions)."
fi

# Auto-pick the device ABI for the Magisk binaries unless the caller overrode it.
if [[ "$ARCH" == "arm64-v8a" ]]; then
  ABI="$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')"
  [[ -n "$ABI" ]] && ARCH="$ABI"
fi

# 1) Extract the Magisk patcher from the APK (it's a plain zip)
note "extracting Magisk patcher from $(basename "$APK") ..."
unzip -o -q "$APK" -d "$WORK/apk"

ASSETS="$WORK/apk/assets"
LIB="$WORK/apk/lib"
[[ -f "$ASSETS/boot_patch.sh" ]] || die "boot_patch.sh not in APK assets/ - is this a real Magisk APK?"

STAGE="$WORK/stage"
mkdir -p "$STAGE"
cp "$ASSETS/boot_patch.sh"     "$STAGE/"
cp "$ASSETS/util_functions.sh" "$STAGE/"
# stub.apk exists on newer Magisk; tolerate its absence on older builds.
[[ -f "$ASSETS/stub.apk" ]] && cp "$ASSETS/stub.apk" "$STAGE/"

# Magisk ships its native binaries as lib*.so; boot_patch.sh expects them under
# specific names in its own dir. The names changed across versions, so stage
# BOTH conventions:
#   modern (v27+/v30.x): magiskboot, magiskinit, magisk (universal), init-ld
#   legacy (older):      magiskboot, magiskinit, magisk64, magisk32
cp "$LIB/$ARCH/libmagiskboot.so"        "$STAGE/magiskboot" || die "libmagiskboot.so missing for arch $ARCH"
cp "$LIB/$ARCH/libmagiskinit.so"        "$STAGE/magiskinit" || die "libmagiskinit.so missing for arch $ARCH"
# Modern single universal binary -> `magisk` (what current boot_patch.sh runs),
# and also copied to `magisk64` so older boot_patch.sh scripts still find it.
if [[ -f "$LIB/$ARCH/libmagisk.so" ]]; then
  cp "$LIB/$ARCH/libmagisk.so" "$STAGE/magisk"
  cp "$LIB/$ARCH/libmagisk.so" "$STAGE/magisk64"
else
  # Legacy split binaries.
  cp "$LIB/$ARCH/libmagisk64.so"        "$STAGE/magisk64"   2>/dev/null || true
  [[ -f "$STAGE/magisk64" ]] && cp "$STAGE/magisk64" "$STAGE/magisk"
fi
cp "$LIB/armeabi-v7a/libmagisk32.so"    "$STAGE/magisk32"   2>/dev/null || true
# init-ld: LD_PRELOAD helper required by modern boot_patch.sh (v30.x).
cp "$LIB/$ARCH/libinit-ld.so"           "$STAGE/init-ld"    2>/dev/null || true
[[ -f "$STAGE/magisk" ]] || die "could not stage the 'magisk' binary from the APK (no libmagisk.so/libmagisk64.so for arch $ARCH)"

cp "$IMAGE" "$STAGE/stock.img"

# 2) Push to the device and run Magisk's own patcher over adb shell
note "staging patcher on device at $DEVICE_TMP ..."
adb shell "rm -rf $DEVICE_TMP && mkdir -p $DEVICE_TMP" >/dev/null
adb push "$STAGE/." "$DEVICE_TMP/" >/dev/null

note "running Magisk boot_patch.sh on device (no GUI) ..."
warn "note: on non-Samsung devices you'll see 'Failed to patch' a few times below."
warn "      those are Magisk's Samsung-only kernel patches (RKP/defex/PROCA) that"
warn "      don't apply to a Pixel/Tensor kernel - they're SKIPPED, not errors."
warn "      Success is confirmed by 'new-boot.img' being produced (checked next)."
adb shell "cd $DEVICE_TMP && chmod 755 * && sh boot_patch.sh stock.img" \
  || die "boot_patch.sh failed on device (see output above)"

# boot_patch.sh writes new-boot.img into its working dir. This - not any
# 'Failed to patch' line above - is the real success signal.
adb shell "test -f $DEVICE_TMP/new-boot.img" \
  || die "expected $DEVICE_TMP/new-boot.img was not produced"
note "boot_patch.sh completed: new-boot.img produced (the 'Failed to patch' lines above were the expected Samsung-only skips)."
note "pulling patched image -> $OUT"
adb pull "$DEVICE_TMP/new-boot.img" "$OUT" >/dev/null
adb shell "rm -rf $DEVICE_TMP" >/dev/null || true

note "patched image ready: $OUT"

# 3) Optional: temporary boot from RAM (writes nothing)
if [[ "$BOOT_TEST" -eq 1 ]]; then
  warn "rebooting to bootloader for a TEMPORARY 'fastboot boot' test (nothing is flashed) ..."
  enter_fastboot
  note "fastboot boot $OUT (temporary root; a normal reboot returns to stock) ..."
  fastboot boot "$OUT" || die "fastboot boot failed"
  note "waiting for Android + adb ..."
  wait_for_boot 180
  if check_root; then
    note "TEMPORARY ROOT CONFIRMED (su -c id -> uid=0). Nothing was written to a partition."
  else
    warn "booted, but 'su -c id' did not report uid=0 yet - with a TEMPORARY boot, Magisk's"
    warn "one-time GUI setup can't persist; use --flash for a durable root, then finalize in-app."
  fi
fi

# 4) Optional: DESTRUCTIVE permanent flash (writes to the partition)
if [[ "$FLASH" -eq 1 ]]; then
  [[ -n "$PART" ]] || die "refusing to flash: unknown root partition for '$DEVICE'"

  if [[ "$ASSUME_YES" -ne 1 ]]; then
    warn "About to PERMANENTLY flash the patched image and WRITE to a partition:"
    warn "    device : ${DEVICE:-unknown}"
    warn "    part   : $PART"
    warn "    image  : $OUT"
    warn "This modifies the device. It is safe ONLY on an unlocked TEST device."
    printf '\033[1;33m[root_pixel]\033[0m Type exactly FLASH to proceed: ' >&2
    read -r reply
    [[ "$reply" == "FLASH" ]] || die "confirmation not received (got '${reply:-}'); aborting without writing."
  else
    warn "--yes given: flashing $PART on ${DEVICE:-unknown} unattended (no prompt)."
  fi

  note "entering bootloader to flash ..."
  enter_fastboot
  assert_fastboot_unlocked
  note "fastboot flash $PART $OUT ..."
  fastboot flash "$PART" "$OUT" || die "fastboot flash $PART failed - device left in bootloader; do NOT reboot into a half-flashed state. Re-run or flash the stock image to recover."
  note "rebooting device ..."
  fastboot reboot || die "fastboot reboot failed (device is in bootloader; run 'fastboot reboot' manually)"
  note "waiting for Android + adb ..."
  wait_for_boot 180
  if check_root; then
    note "PERMANENT ROOT CONFIRMED (su -c id -> uid=0) on ${DEVICE:-device}. Done."
  else
    warn "flashed and rebooted; root not active YET - Magisk needs its one-time setup."
    finalize_magisk "$APK"
  fi
fi

# Final guidance (only when we did NOT already flash)
if [[ "$FLASH" -ne 1 ]]; then
cat >&2 <<EOF

$(note "next step - make it PERMANENT (you run this, it WRITES to the partition):")
  # Pixel 7/8/9/10/11+ (init_boot):  adb reboot bootloader && fastboot flash init_boot "$OUT" && fastboot reboot
  # Pixel 6 / 6a       (boot)     :  adb reboot bootloader && fastboot flash boot      "$OUT" && fastboot reboot
  # then verify:                     adb shell su -c id      # expect uid=0(root)
$( [[ -n "$PART" ]] && printf '\n  # detected %s -> flash the "%s" partition:\n  adb reboot bootloader && fastboot flash %s "%s" && fastboot reboot\n' "$DEVICE" "$PART" "$PART" "$OUT" )
  # or let this script do it:  add --flash (typed confirm) or --flash --yes (unattended)
See README "Rooting Android & jailbreaking iOS (test devices)" for the full walkthrough.
EOF
fi
