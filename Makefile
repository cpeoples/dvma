# DVMA local validation entrypoints. `make check` is the single command a
# contributor runs before opening a PR; it mirrors the fast half of CI.
#
#   make check      fast gate: format, analyze, generator drift, app-id, schema, standards, workflows
#   make test       check + full Dart unit/widget suite (`flutter test`)
#   make check-all  test + the whole pre-commit suite (multi-language lint/format/secret)
#   make ci-local   closest local mirror of the required PR CI jobs
#   make fix        auto-fix formatting (dart format, and pre-commit auto-fixers)
#   make generate   regenerate the registry/router/manifest from the YAML
#   make docs       build the Hugo documentation site locally
#
# `make check` is Dart-focused for speed, plus a fast actionlint pass over the
# workflows (see `workflows`) so a shell/Actions edit CI would reject is caught
# before pushing. The full multi-language gate (Python via ruff, JS via prettier,
# Markdown, YAML, secrets) runs under `make check-all` / `make precommit`.
# `flutter test` and the native harness compiles (companion APK / androidTest /
# iOS RunnerUITests, i.e. the Kotlin/Swift/C syntax gate) are intentionally NOT
# in `make check`: they are slower and belong in CI. `make ci-local` runs the
# ones that work without a device.

.DEFAULT_GOAL := check
.PHONY: check test check-all ci-local fix generate docs precommit \
        format analyze drift appid schema standards versions workflows \
        companion androidtest help

help:
	@grep -E '^# ' $(firstword $(MAKEFILE_LIST)) | sed 's/^# \{0,1\}//' | sed '/^$$/q'

# --- Fast gate (mirrors the fast half of CI) ---------------------------------

check: format analyze drift appid schema standards versions workflows
	@echo "make check: OK"

format:
	dart format --output=none --set-exit-if-changed lib tool test integration_test

analyze:
	flutter analyze

drift: generate
	@git diff --exit-code -- lib/vulnerability_registry.dart lib/core/module_router.dart automation/vuln_manifest.json \
		|| { echo "Generated files are out of date. Run 'make generate' and commit the result."; exit 1; }

appid:
	dart run tool/sync_app_id.dart --check

schema:
	python3 automation/scripts/validate_registry.py
	python3 automation/scripts/validate_registry.py --self-test

# Every MASVS/CWE/MASWE/MASTG id is well-formed and resolves to a real
# mas.owasp.org page (no invented or dangling standard ids).
standards:
	python3 automation/scripts/standards_mapping_audit.py --check

# Gradle wrapper, Flutter (ci vs .tool-versions) and iOS target/Swift all match
# gradle/libs.versions.toml (the versions the catalog can't set itself).
versions:
	python3 automation/scripts/check_versions.py

# GitHub Actions workflow lint (actionlint, which also shellcheck-lints every
# run: script). This is the fast gate for the .github/workflows/ surface, so a
# workflow/shell edit that CI's shellcheck would reject (e.g. SC2012) is caught
# here rather than only after a push. Uses actionlint if installed, else the
# pinned pre-commit hook; if neither is present it prints how to get one and
# does not fail the build (CI still enforces it).
workflows:
	@if command -v actionlint >/dev/null 2>&1; then \
		actionlint; \
	elif command -v pre-commit >/dev/null 2>&1; then \
		pre-commit run --all-files actionlint; \
	else \
		echo "workflows: skipped (install 'actionlint' via 'brew install actionlint',"; \
		echo "  or 'pip install pre-commit' to run the pinned hook). CI still enforces this."; \
	fi

# --- Deeper gates ------------------------------------------------------------

test: check
	flutter test

check-all: test precommit

precommit:
	pre-commit run --all-files

# Closest local mirror of the required PR CI jobs (no device/emulator needed).
ci-local: check
	flutter test
	@echo "make ci-local: OK (integration + native compiles run in CI)"

# --- Utilities ---------------------------------------------------------------

fix:
	dart format lib tool test integration_test
	pre-commit run --all-files ruff ruff-format prettier || true

generate:
	dart run tool/generate.dart

docs:
	python3 .hugo/scripts/build_docs.py
	cd .hugo && hugo --minify

# Native harness compiles (these need Android SDK / Xcode; run in CI too).
companion:
	cd companion/dvma-attacker && ./gradlew :app:assembleDebug

androidtest:
	cd android && ./gradlew :app:assembleDebugAndroidTest -PdvmaAndroidTest=true
