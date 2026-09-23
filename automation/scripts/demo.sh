#!/usr/bin/env bash
#
# DVMA companion-attacker demos - single entry point. FOR AUTHORIZED
# SECURITY-TRAINING USE ONLY.
#
# Each subcommand runs one focused cross-app demo against a connected Android
# device: it installs DVMA + the separately-signed companion attacker, drives
# the vulnerable flow, and asserts the effect crosses the process/trust
# boundary. The subcommands delegate to the dedicated scripts next to this one,
# so every env override they document (SERIAL, SKIP_BUILD, FLAVOR, ADB, …) works
# unchanged here too.
#
# Usage:
#   automation/scripts/demo.sh otp          # cross-app OTP / credential leak
#   automation/scripts/demo.sh broadcast    # broadcast-IPC modules (spoof/forge/leak)
#   automation/scripts/demo.sh components    # exported Activities/Service + task hijack
#
#   SKIP_BUILD=1 automation/scripts/demo.sh broadcast   # reuse built APKs
#   SERIAL=<serial> automation/scripts/demo.sh otp      # target a specific device
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib/common.sh"

usage() {
  cat <<'EOF'
DVMA companion-attacker demos.

Usage: automation/scripts/demo.sh <command>

Commands:
  otp          Cross-app OTP / credential leak (unprotected vs permission-scoped broadcast)
  broadcast    Broadcast-IPC modules: receive-side spoof/forge + send-side implicit/ordered/role
  components   Exported Activities/Service + task-stack (StrandHogg) hijack

Env overrides (forwarded to the underlying script):
  SERIAL=<serial>   target a specific device (else the sole attached one)
  SKIP_BUILD=1      reuse already-built APKs
  FLAVOR=<path>     dart-define flavor (default config/flavors/full.json)
  ADB=<path>        explicit adb binary

Docs: https://cpeoples.github.io/dvma/manual-testing/
EOF
}

case "${1:-}" in
  otp)         exec "$HERE/demo_cross_app_otp.sh" ;;
  broadcast)   exec "$HERE/demo_broadcast_ipc.sh" ;;
  components)  exec "$HERE/demo_exported_components.sh" ;;
  -h|--help|help|"") usage; [[ -n "${1:-}" ]] ;;
  *) bad "unknown command: $1"; echo; usage; exit 2 ;;
esac
