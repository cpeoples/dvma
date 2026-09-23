# Contributing to DVMA

DVMA is a deliberately vulnerable mobile app for **authorized** security
training and research. Contributions that add real, well-mapped vulnerability
modules - or improve the tooling, docs, and platform parity around them - are
welcome. Please read this before opening a PR.

> **Scope reminder.** Every module must be a *training artifact*: a self-contained
> demonstration inside DVMA. Do not contribute exploits, payloads, or tooling
> aimed at third-party apps, services, or infrastructure you are not authorized
> to test.

## The registry is the single source of truth

Vulnerability metadata is authored in **one** place - the YAML registry under
`config/registry/categories/` - and everything else is generated from it:

- `lib/vulnerability_registry.dart` + `lib/core/module_router.dart` (the app)
- `automation/vuln_manifest.json` (drives the Appium/Espresso/XCUITest walks)
- `docs/vulnerabilities/<id>.md` and every Hugo docs page
- the platform-split **Manual Testing** checklists (from each module's
  `manual_test:` field)

**You never hand-edit generated files.** Run the generator and commit its output.

## Adding a vulnerability module

1. **Add one YAML entry** under the correct category in
   `config/registry/categories/<category>.yaml` (large categories are a
   directory of numbered shards, e.g. `platform/NN_*.yaml` - append to the right
   shard). See the full field guide in
   [`docs/getting-started/automation.md`](docs/getting-started/automation.md).
2. **Run the generator** and commit its output:

   ```sh
   dart run tool/generate.dart
   ```

   It scaffolds a screen stub and a doc stub for a new `id` if none exist.
3. **Implement the behavior** in the generated screen, add an `integration_test/`
   flow, and a unit test for any helper logic.
4. **Run the local gate** before pushing (mirrors CI):

   ```sh
   make check      # format, analyze, generator drift, app-id sync, registry schema, standards links, workflow lint
   make test       # the above + the full Dart unit/widget suite
   ```

   Install the commit-time gate once so these run automatically on every commit:

   ```sh
   pip install pre-commit && pre-commit install
   ```

   On **Windows**, run these from WSL or Git Bash, or (since `make` isn't
   standard there) run the underlying `dart` / `flutter` / `python3` commands
   directly, or just rely on the `pre-commit` hook, which runs natively on any
   OS. See [Linting & code quality](https://cpeoples.github.io/dvma/getting-started/automation/#linting--code-quality)
   for the exact command list.
5. **Open a pull request** against `main`. Fork the repo (or push a branch if you
   have write access), commit with a message that explains *why* the module is a
   real weakness, and open the PR. CI re-runs the same gate plus the native
   compiles (see [What CI checks on your PR](#what-ci-checks-on-your-pr)); a green
   run means your contribution meets the bar.

### Required, enforced standards tags

Every module **must** carry a genuine mapping for all four of:

| Field | Example | Notes |
| --- | --- | --- |
| `masvs` | `MASVS-CRYPTO-1` | at least one MASVS control |
| `cwe` | `CWE-327` | at least one CWE |
| `maswe` | `MASWE-0007` | at least one MASWE weakness id |
| `owasp_mobile` | `M10` | OWASP Mobile Top 10 (2024) category |

`dart run tool/generate.dart` (which CI runs) **exits non-zero and names any
module missing one**, so a PR without full standards mapping fails the build.
A second gate, `standards_mapping_audit.py --check` (in pre-commit and CI),
additionally verifies every MASVS/CWE/MASWE/MASTG id is well-formed **and
resolves to a real `mas.owasp.org` page**, so a mistyped or invented id fails
too. Map honestly: never invent an id to satisfy the gate; if a standard has no
genuine match, that's usually a sign the module needs rethinking. `owasp_llm` /
`owasp_agentic` and `mastg_v2` / `mastg_demo` are optional and added only when a
real mapping exists.

DVMA has no *required* `severity` field: modules map to CWE/MASWE/OWASP (which
carry the standard severity framing) rather than a second, mandatory scale. An
**optional** `severity` (`low` | `medium` | `high` | `critical`) may be added
when a module has a defensible rating; it is enum-validated but never
fabricated to fill a column. The `difficulty` field (`easy` | `medium` | `hard`)
sorts a module within its category.

### Platform applicability

- Shared cross-platform class: omit `platforms:` (defaults to both). Add a
  `platform_note:` if the behavior differs per OS, and split OS-specific tools
  into `tools_android:` / `tools_ios:`.
- Platform-specific class: `platforms: [android]` or `platforms: [ios]`.

The `platforms` value drives which Manual Testing page a module appears on, so
set it accurately.

### Manual-test steps (optional)

If a module needs an external/manual verification step the in-app
`integration_test/` suite structurally can't drive (active MITM, Frida, drozer,
static APK/IPA analysis), add a `manual_test:` line. It's rendered into the
platform-split Manual Testing checklist (Android + iOS sub-pages) on the docs
site automatically. Omit it for modules fully proven in-app.

## App id

`config/app.json` is the single source of truth for the application/bundle id.
After changing it, run `dart run tool/sync_app_id.dart` (CI verifies with
`--check`).

## What CI checks on your PR

The `CI` workflow (`.github/workflows/ci.yml`) runs on every PR to `main`:

| Job | Runner | What it proves | Reproduce locally |
| --- | --- | --- | --- |
| **Lint & validate (pre-commit)** | Ubuntu | Formatting + lint across languages (Dart, Python/ruff, JS/prettier, Markdown, YAML, JSON, shell/shellcheck, Actions/actionlint), registry schema, standards-link resolution, secret scan | `make check-all` |
| **Analyze & unit/widget tests** | Ubuntu | Generator/app-id in sync, `flutter analyze`, `flutter test` | `make test` |
| **Integration tests (Android emulator)** | Ubuntu | The full `integration_test/` walk | `flutter test integration_test` |
| **Build smoke (debug APK)** | Ubuntu | The app compiles to an Android binary | `flutter build apk --debug` |
| **Build companion attacker** | Ubuntu | The cross-app demo companion compiles | `make companion` |
| **Compile Android instrumentation** | Ubuntu | The Espresso/UiAutomator harness compiles | `make androidtest` |
| **Compile iOS XCUITest harness** | macOS | Runner + RunnerUITests compile (no signing) | see below |

The iOS harness compile reproduces locally with:

```sh
flutter build ios --simulator --debug
xcodebuild build-for-testing -workspace ios/Runner.xcworkspace \
  -scheme Runner -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO
```

No secrets are needed for any of the above. iOS simulator integration and the
iOS build smoke are available on demand (`workflow_dispatch`); macOS runners are
slower/costlier so they are not part of the required PR gate. Tagged releases
(`v*`) run a separate `Release` workflow (`.github/workflows/release.yml`) that
builds and **signs** the Android APK/AAB (and, when Apple secrets exist, a
`.ipa`) - see
[`docs/getting-started/ci-and-releases.md`](docs/getting-started/ci-and-releases.md).

## What each component is

A quick glossary so you know what you are touching:

| Component | Path | Purpose |
| --- | --- | --- |
| Registry | `config/registry/categories/**` | The single source of truth: one YAML entry per module. |
| Registry schema | `config/registry/schema/module.schema.json` | Declarative contract for a module entry (validated in pre-commit/CI). |
| Generator | `tool/generate.dart` | Validates the registry and generates the catalog, router, manifest, and stubs. |
| Generated catalog/router | `lib/vulnerability_registry.dart`, `lib/core/module_router.dart` | Consumed by the app; never hand-edited. |
| Automation manifest | `automation/vuln_manifest.json` | Machine-readable module list that drives the walks. |
| Module screen | `lib/modules/<category>/<id>/` | The Flutter UI for a module (stub scaffolded, behavior hand-written). |
| Unit/widget tests | `test/` | Regression suites asserting the intended behavior still holds. |
| Integration suite | `integration_test/app_test.dart` | Boots the app and asserts every module has a registered screen. |
| Companion attacker | `companion/dvma-attacker/` | A standalone app used only to demonstrate cross-app boundary crossings. |
| Android instrumentation | `android/app/src/androidTest/` | UiAutomator "walk every module" harness (opt-in with `-PdvmaAndroidTest=true`). |
| iOS XCUITest | `ios/RunnerUITests/` | The native iOS "walk every module" harness. |
| Appium harness | `automation/appium/` | Cross-platform WebdriverIO walk driver. |
| Validators | `tool/generate.dart`, `automation/scripts/validate_registry.py` | Enforce the contribution contract. |

The copies under `automation/xcuitest/` and `automation/espresso/` are reference
copies for reading; the wired-in tests under `ios/RunnerUITests/` and
`android/app/src/androidTest/` are the ones CI compiles.

## Troubleshooting: common failures and fixes

Every failure below is caught locally by `make check` (or the pre-commit hook)
before you push:

| Symptom | Cause | Fix |
| --- | --- | --- |
| `ERROR: [cat/id] unknown field "X"` | Misspelled/unsupported field | Use a field from the schema (`config/registry/schema/module.schema.json`). |
| `ERROR: [cat/id] duplicate id` | Two modules share an `id` | Rename one; ids are globally unique. |
| `ERROR: [cat/id] missing required non-empty "detail"/"title"/"summary"` | Empty or omitted prose field | Add real prose; these drive the app screen and the docs. |
| `ERROR: ... must have a top-level "<cat>:" key` / `unknown category` | Misspelled category key, or a shard's top key doesn't match its folder | Match the top-level key to the category id (a mismatched key is silently dropped otherwise). |
| `ERROR: [cat/id] is missing required "masvs"/"cwe"/...` | Omitted required standards tag | Add a genuine mapping for all four required tags. |
| `ERROR: [cat/id] cwe entry "X" is malformed` | Wrong id shape | Use `CWE-<n>`, `MASWE-<n>`, `MASVS-<AREA>-<n>`, `M<n>`. |
| `standards_mapping_audit: ... unresolved ... standard id(s)` | A well-formed MASWE/MASTG id has no real `mas.owasp.org` page | Use a real id, or add its path to `.hugo/scripts/mas_links.json` if the page exists. |
| `ERROR: [cat/id] reference "X" must be "text\|https://url"` | Reference not `text\|url`, or a `:` in unquoted YAML made it a map | Quote the string and use the `text\|https://url` format. |
| `ERROR: [cat/id] has unknown platform "X"` | Bad `platforms:` value | Use `android` and/or `ios`. |
| `Generated files are out of date` | Forgot to run the generator | `make generate` and commit the result. |
| `app id drift detected` | Changed `config/app.json` without syncing | `dart run tool/sync_app_id.dart` and commit. |
| Malformed YAML (parse error) | Bad indentation / unquoted special chars | Fix the YAML; `check-yaml` and `yamllint` pinpoint the line. |
| `flutter analyze` failure | Lint/type error in a screen | Fix the reported line; run `make analyze`. |
| Companion won't compile | Broke `companion/dvma-attacker/` sources | `make companion` locally to see the Gradle error. |
| Android instrumentation won't compile | Broke `android/app/src/androidTest/` | `make androidtest` locally. |
| iOS XCUITest won't compile | Broke `ios/RunnerUITests/` | Run the `xcodebuild build-for-testing` command above. |
| `check-added-large-files` blocks the commit | Committing a build artifact/binary | Remove it; large outputs are gitignored, not committed. |

## Generated docs

`docs/ios_parity_audit.md` is generated from the registry (it's linked from the
architecture "real-artifact guarantee" page, so it's committed and kept in
sync). Regenerate it after registry/bridge changes:

```sh
python3 automation/scripts/ios_parity_audit.py     # docs/ios_parity_audit.md (committed)
```

Two more coverage reports share the same pattern but are **gitignored** (nothing
links to them - regenerate on demand only when you want to review coverage):

```sh
dart run tool/evidence_matrix.dart                    # docs/evidence-matrix.md
python3 automation/scripts/standards_mapping_audit.py # docs/standards_mapping_audit.md
```

The standards audit doubles as a gate: `standards_mapping_audit.py --check`
(run by pre-commit and CI) writes no file and fails if any standard id is
malformed or does not resolve to a real `mas.owasp.org` page.

The per-module pages under `docs/vulnerabilities/<id>.md` are generated
scaffolds: the generator writes one when a module is first added, carrying the
module's metadata plus a short "Reproduce in the app" section and a
`<!-- dvma:generated-stub -->` marker. The published docs site does not use the
scaffold's prose - it renders a full step-by-step exploit playbook for every
module directly from the registry, so there is nothing to fill in by hand. If
you want a hand-authored page for a specific module, edit its file and remove
the `dvma:generated-stub` marker; the site then uses your prose verbatim.

## Style

- **Dart/Flutter** is the only linted surface: `flutter analyze` (with
  `flutter_lints`) must pass. `android/` and `ios/` are excluded - their native
  linters run under Gradle/Xcode.
- Keep code intentional and human-authored: no dead abstractions, no redundant
  comments, no defensive checks the surrounding code already guarantees.
- Write commit messages and PR descriptions that explain *why*, not just *what*.
- Visual identity (icons, splash, design tokens) is documented in
  [`docs/branding.md`](docs/branding.md); keep it in sync if you change brand
  assets under `assets/branding/`.
