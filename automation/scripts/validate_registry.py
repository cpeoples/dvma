#!/usr/bin/env python3
"""Validate every registry module against config/registry/schema/module.schema.json.

tool/generate.dart is the authoritative gate; this is the fast, declarative
first line used by pre-commit and CI. It loads each category YAML, extracts the
`vulnerabilities:` entries, and validates them against the JSON Schema.

Two modes:

  validate_registry.py              # validate the live registry (default)
  validate_registry.py --self-test  # prove the schema rejects known-bad modules

Requires `jsonschema` (managed by the pre-commit env / installed in CI). If it
is not importable, the script exits 0 with a skip notice so it never blocks a
contributor who only ran `python3 automation/scripts/validate_registry.py`
directly without the dependency; the Dart generator still enforces the contract.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
CATEGORIES = ROOT / "config" / "registry" / "categories"
SCHEMA = ROOT / "config" / "registry" / "schema" / "module.schema.json"
META = ROOT / "config" / "registry" / "meta.yaml"

# A minimal module that satisfies every required field, used as the base for the
# self-test negative cases (each case mutates one thing to make it invalid).
_VALID_MODULE = {
    "id": "self_test_module",
    "title": "Self-test module",
    "difficulty": "medium",
    "masvs": ["MASVS-CRYPTO-1"],
    "maswe": ["MASWE-0001"],
    "cwe": ["CWE-327"],
    "owasp_mobile": "M10",
    "summary": "One-line summary.",
    "detail": "Longer detail.",
}

# (description, module) pairs the schema MUST reject. Mirrors the contributor
# mistakes tool/generate.dart also catches; keeping a declarative copy here
# proves the schema itself is a real gate, not a rubber stamp.
_INVALID_CASES = [
    ("missing required field (detail)", {k: v for k, v in _VALID_MODULE.items() if k != "detail"}),
    ("unknown field", {**_VALID_MODULE, "platfrom": ["android"]}),
    ("bad id shape (uppercase)", {**_VALID_MODULE, "id": "BadId"}),
    ("invalid difficulty enum", {**_VALID_MODULE, "difficulty": "trivial"}),
    ("invalid severity enum", {**_VALID_MODULE, "severity": "sev1"}),
    ("malformed cwe", {**_VALID_MODULE, "cwe": ["327"]}),
    ("malformed masvs", {**_VALID_MODULE, "masvs": ["MASVS-1"]}),
    ("malformed owasp_mobile", {**_VALID_MODULE, "owasp_mobile": "MOBILE-10"}),
    ("invalid platform", {**_VALID_MODULE, "platforms": ["windows"]}),
    ("reference missing url", {**_VALID_MODULE, "references": ["just text, no pipe"]}),
]


def self_test() -> int:
    """Assert the schema accepts a valid module and rejects each known-bad one."""
    try:
        import jsonschema
    except ImportError:
        print("validate_registry --self-test: jsonschema not installed; skipping.")
        return 0

    validator = jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text()))

    failures: list[str] = []
    if list(validator.iter_errors(_VALID_MODULE)):
        failures.append("the known-valid module was rejected by the schema")
    for desc, module in _INVALID_CASES:
        if not list(validator.iter_errors(module)):
            failures.append(f"schema accepted an invalid module: {desc}")

    if failures:
        print("validate_registry --self-test: FAILED", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(
        f"validate_registry --self-test: schema accepts the valid module and "
        f"rejects all {len(_INVALID_CASES)} invalid cases."
    )
    return 0


def main() -> int:
    try:
        import jsonschema
    except ImportError:
        print(
            "validate_registry: jsonschema not installed; skipping "
            "(tool/generate.dart still enforces the contract)."
        )
        return 0

    schema = json.loads(SCHEMA.read_text())
    validator = jsonschema.Draft202012Validator(schema)

    meta = yaml.safe_load(META.read_text()) if META.exists() else {}
    known_categories = set(meta.get("category_order") or [])

    errors: list[str] = []
    seen: dict[str, str] = {}
    module_count = 0

    for path in sorted(CATEGORIES.rglob("*.yaml")):
        doc = yaml.safe_load(path.read_text())
        if not isinstance(doc, dict):
            continue
        rel = path.relative_to(ROOT)
        for category, body in doc.items():
            if known_categories and category not in known_categories:
                errors.append(
                    f"{rel}: unknown category '{category}' "
                    f"(not in meta.yaml category_order). Modules under it are "
                    f"silently dropped by the generator."
                )
                continue
            if not isinstance(body, dict):
                continue
            for module in body.get("vulnerabilities") or []:
                if not isinstance(module, dict):
                    errors.append(f"{rel}: a vulnerabilities entry is not a mapping")
                    continue
                module_count += 1
                mid = module.get("id", "<no id>")
                for err in sorted(validator.iter_errors(module), key=str):
                    field = "/".join(str(p) for p in err.absolute_path) or "(root)"
                    errors.append(f"{rel} :: {mid} :: {field}: {err.message}")
                if isinstance(mid, str):
                    prior = seen.get(mid)
                    if prior:
                        errors.append(f"{rel} :: {mid}: duplicate id (also in {prior})")
                    else:
                        seen[mid] = str(rel)

    if errors:
        print(
            f"validate_registry: {len(errors)} problem(s) in " f"{module_count} modules:",
            file=sys.stderr,
        )
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    print(f"validate_registry: {module_count} modules valid against the schema.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove the schema rejects known-bad modules (does not read the "
        "live registry); used by CI to verify the gate is real.",
    )
    args = parser.parse_args()
    sys.exit(self_test() if args.self_test else main())
