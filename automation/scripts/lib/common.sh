# DVMA harness common helpers - source this from a script:
#   . "$(dirname "$0")/lib/common.sh"
#
# shellcheck shell=bash
# Provides the coloured say/note/ok/bad printers plus doc-aware failure output.
# When a prerequisite is missing, call `die` with a reason and a docs slug so the
# message tells the user both *what* is missing and *where* the fix is documented.
#
# The docs site deploys to GitHub Pages for github.com/cpeoples/dvma, i.e.
#   https://cpeoples.github.io/dvma/<slug>/
# `docs` prints an absolute link to that base by default. Override the base with
# DVMA_DOCS_URL (e.g. a custom domain, a fork's Pages URL, or "/" + local
# preview) if you host the docs somewhere else.

say()  { printf '\n\033[1;33m▶ %s\033[0m\n' "$*"; }
note() { printf '  \033[0;36m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[0;32m✓ %s\033[0m\n' "$*"; }
bad()  { printf '  \033[0;31m✗ %s\033[0m\n' "$*"; }

DVMA_DOCS_URL="${DVMA_DOCS_URL:-https://cpeoples.github.io/dvma}"

# docs <slug> - print a pointer to a docs page. <slug> is a Hugo path such as
# "getting-started/#nodejs" or "device-access/".
docs() {
  note "docs: ${DVMA_DOCS_URL%/}/${1#/}"
}

# die <reason> [docs-slug] - print the failure reason, an optional docs pointer,
# then exit 1. Use for missing-prerequisite bailouts.
die() {
  bad "$1"
  [[ -n "${2:-}" ]] && docs "$2"
  exit 1
}
