# DVMA local validation entrypoints. `make check` is the single command a
# contributor runs before opening a PR; it mirrors the fast half of CI.
#
#   make check      fast gate: format, analyze, generator drift, app-id, schema, standards
#   make test       check + full Dart unit/widget suite (`flutter test`)
#   make check-all  test + the whole pre-commit suite (multi-language lint/format/secret)
#   make ci-local   closest local mirror of the required PR CI jobs
#   make fix        auto-fix formatting (dart format, and pre-commit auto-fixers)
#   make generate   regenerate the registry/router/manifest from the YAML
#   make docs       build the Hugo documentation site locally
#
# `make check` is Dart-focused for speed. The full multi-language gate (Python
# via ruff, JS via prettier, Markdown, YAML, shell, GitHub Actions, secrets) runs
# under `make check-all` / `make precommit`. `flutter test` and the native
# harness compiles (companion APK / androidTest / iOS RunnerUITests, i.e. the
# Kotlin/Swift/C syntax gate) are intentionally NOT in `make check`: they are
# slower and belong in CI. `make ci-local` runs the ones that work without a device.

.DEFAULT_GOAL := check
.PHONY: check test check-all ci-local fix generate docs precommit \
        format analyze drift appid schema standards versions companion androidtest help

help:
	@grep -E '^# ' $(firstword $(MAKEFILE_LIST)) | sed 's/^# \{0,1\}//' | sed '/^$$/q'

# --- Fast gate (mirrors the fast half of CI) ---------------------------------

check: format analyze drift appid schema standards versions
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
