# `automation/scripts/`

Helper scripts for building, driving, verifying, and reporting on DVMA. Run them
from the **repo root** (paths are relative to it), e.g.:

```sh
automation/scripts/appium_run_android.sh
```

Most bailouts print a docs link alongside the error; override the docs base with
`DVMA_DOCS_URL=` (default `https://cpeoples.github.io/dvma`). Full guides live in
the [docs site](https://cpeoples.github.io/dvma/) - this file is just the index.

## One-shot UI-automation harnesses

Build the app, run the full module walk, and collect on-device evidence in one
command. Need **Node.js 18+** (Appium/WebdriverIO).

| Script | What it does | OS |
| --- | --- | --- |
| `appium_run_android.sh` | Resolve device/emulator + JDK + adb, build the debug APK, run the Appium (UiAutomator2) walk, pull artifacts. | macOS / Linux |
| `appium_run_ios.sh` | Boot a Simulator, build the `.app`, run the Appium (XCUITest) walk, pull artifacts. | macOS |

## Native capture harnesses

Run the platform's own UI-test walk (no Node) and assemble a capture report.

| Script | What it does | OS |
| --- | --- | --- |
| `capture_run.sh` | Android UiAutomator "walk every module" instrumentation test, capturing what each module actually does. | macOS / Linux |
| `capture_run_ios.sh` | iOS XCUITest walk on a Simulator, pulling per-module artifacts + os_log. | macOS |
| `capture_listener.py` | Dependency-free HTTP/HTTPS sink that logs requests, so real network modules have a live endpoint to hit. | any (Python 3) |
| `build_capture_report.py` | Assemble the capture report from logcat evidence + pulled sink files. | any (Python 3) |

## Companion-attacker demos

Prove a vulnerability crosses a real process/trust boundary using the
separately-signed `com.dvma.attacker` app. **Start here:** `demo.sh` is the
single entry point; the three scripts below are its hardware-validated backends.

| Script | What it does | OS |
| --- | --- | --- |
| `demo.sh <otp\|broadcast\|components>` | Dispatcher for the three demos below (forwards `SERIAL`, `SKIP_BUILD`, `FLAVOR`, `ADB`). | macOS / Linux |
| `demo_cross_app_otp.sh` | Cross-app OTP / credential leak: unprotected broadcast harvested vs permission-scoped broadcast blocked. | macOS / Linux |
| `demo_broadcast_ipc.sh` | Broadcast-IPC modules: receive-side spoof/forge + send-side implicit/ordered/role-delegate. | macOS / Linux |
| `demo_exported_components.sh` | Exported Activities/Service + task-stack (StrandHogg) hijack. | macOS / Linux |

## Static analysis & manifest tooling

Deterministic generators over the module tree / manifest (no device needed).

| Script | What it does | OS |
| --- | --- | --- |
| `inspect_modules.py` | Static fidelity inspection of every module (writes `automation/artifacts/module_inspection.*`). | any (Python 3) |
| `fidelity_audit.py` | Senior-researcher fidelity verdict per module (REAL-IO / REAL-NATIVE / REAL-CRYPTO / …) - stricter than `inspect_modules.py`; writes `automation/artifacts/fidelity_audit.{md,json}`. | any (Python 3) |
| `enrich_manifest.py` | Fold per-module evidence descriptions into `automation/vuln_manifest.json`. | any (Python 3) |
| `ios_parity_audit.py` | Generate `docs/ios_parity_audit.md` (per-module iOS evidence tier). | any (Python 3) |
| `standards_mapping_audit.py` | Generate `docs/standards_mapping_audit.md` (per-module MASVS/MASWE/MASTG coverage). | any (Python 3) |

## Device provisioning

| Script | What it does | OS |
| --- | --- | --- |
| `verify_all_modules.sh` | Android-only: walk every module via UiAutomator and record pass/fail (no Node/Appium). | macOS / Linux |
| `root_pixel.sh` | Headless Magisk boot-image patcher for Pixel test devices (patches only; you flash). | macOS / Linux |

## `lib/`

Sourced by the shell harnesses; not run directly.

| File | What it provides |
| --- | --- |
| `lib/common.sh` | Coloured `say`/`note`/`ok`/`bad` printers, plus `docs <slug>` / `die <reason> <slug>` for doc-linked failure output. |

> **Windows:** the shell harnesses target macOS/Linux (and iOS work is macOS-only
> regardless). On Windows use WSL, or drive the cross-platform Node path directly
>
> - see `automation/appium/` and the
> [automation guide](https://cpeoples.github.io/dvma/getting-started/automation/).
