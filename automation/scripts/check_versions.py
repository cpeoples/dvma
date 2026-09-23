#!/usr/bin/env python3
"""Check that versions the Gradle catalog can't apply itself stay in sync with it.

gradle/libs.versions.toml is the source of truth for Android versions. Three are
pinned in tool-specific files that can't read it; this gate fails if they drift:

  * both Gradle wrappers vs the catalog `gradle` key,
  * ci.yml/release.yml env.FLUTTER_VERSION vs .tool-versions,
  * the iOS deployment target / Swift version vs the catalog mirror keys.

Usage: python3 automation/scripts/check_versions.py  (run from the repo root).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _catalog_version(key: str) -> str:
    toml = (ROOT / "gradle/libs.versions.toml").read_text()
    m = re.search(rf'^\s*{re.escape(key)}\s*=\s*"([^"]+)"', toml, re.MULTILINE)
    if not m:
        sys.exit(f"gradle/libs.versions.toml is missing [versions].{key}")
    return m.group(1)


def _wrapper_gradle(path: str) -> str:
    props = (ROOT / path).read_text()
    m = re.search(r"gradle-([0-9.]+)-(?:all|bin)\.zip", props)
    if not m:
        sys.exit(f"{path} has no gradle-<version> distributionUrl")
    return m.group(1)


def _flutter_tool_versions() -> str:
    m = re.search(r"^flutter\s+([0-9.]+)", (ROOT / ".tool-versions").read_text(), re.MULTILINE)
    if not m:
        sys.exit(".tool-versions has no flutter pin")
    return m.group(1)


def _workflow_flutter(path: str) -> str:
    m = re.search(r'FLUTTER_VERSION:\s*"([0-9.]+)"', (ROOT / path).read_text())
    if not m:
        sys.exit(f"{path} has no env.FLUTTER_VERSION")
    return m.group(1)


def _pbxproj_values(setting: str) -> set[str]:
    text = (ROOT / "ios/Runner.xcodeproj/project.pbxproj").read_text()
    return set(re.findall(rf"{setting} = ([0-9.]+);", text))


def main() -> int:
    errors: list[str] = []

    gradle = _catalog_version("gradle")
    for wrapper in (
        "android/gradle/wrapper/gradle-wrapper.properties",
        "companion/dvma-attacker/gradle/wrapper/gradle-wrapper.properties",
    ):
        found = _wrapper_gradle(wrapper)
        if found != gradle:
            errors.append(
                f"{wrapper}: Gradle {found} != catalog gradle={gradle}. "
                f"Set both wrappers to {gradle} (or update the catalog)."
            )

    flutter = _flutter_tool_versions()
    for wf in (".github/workflows/ci.yml", ".github/workflows/release.yml"):
        found = _workflow_flutter(wf)
        if found != flutter:
            errors.append(
                f"{wf}: FLUTTER_VERSION {found} != .tool-versions {flutter}."
            )

    ios_target = _catalog_version("iosDeploymentTarget")
    targets = _pbxproj_values("IPHONEOS_DEPLOYMENT_TARGET")
    if targets != {ios_target}:
        errors.append(
            f"ios project IPHONEOS_DEPLOYMENT_TARGET {sorted(targets)} != "
            f"catalog iosDeploymentTarget={ios_target}."
        )

    swift = _catalog_version("swift")
    swifts = _pbxproj_values("SWIFT_VERSION")
    if swifts != {swift}:
        errors.append(
            f"ios project SWIFT_VERSION {sorted(swifts)} != catalog swift={swift}."
        )

    if errors:
        print("Version drift detected:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(
            "\nEdit gradle/libs.versions.toml and the file(s) above so they match. "
            "See docs/getting-started/build-and-flavors.md (Toolchain versions).",
            file=sys.stderr,
        )
        return 1

    print("versions: OK (wrappers, Flutter, iOS target/Swift all match the catalog)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
