#!/usr/bin/env bash
# Convenience wrapper: the one command to validate your work before a PR.
# Delegates to `make check` (format, analyze, generator drift, app-id, schema).
# Pass any make target to run something else, e.g. `scripts/check.sh test`.
set -euo pipefail
cd "$(dirname "$0")/.."
exec make "${@:-check}"
