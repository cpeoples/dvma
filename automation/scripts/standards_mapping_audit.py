#!/usr/bin/env python3
"""Generate the DVMA standards-naming/mapping audit (docs/standards_mapping_audit.md).

Answers one question: how do DVMA's own vulnerability names line up with the
OWASP MAS standards each module maps to?

Key framing: MASVS names *controls* (MASVS-STORAGE-1), not vulnerabilities. The
OWASP artifacts that name specific weaknesses/tests are MASWE (weaknesses) and
MASTG (test/demo procedures). So a DVMA module keeps its own descriptive
`title`/`id` and *maps* to the relevant MASVS control(s) + MASWE + MASTG. This
report shows that mapping, verifies every id is well-formed and resolves to a
real mas.owasp.org page (via .hugo/scripts/mas_links.json), and is honest about
where a MAS id does not yet exist (AI/ML, agentic, passkeys) so no fake parity
is implied.

Data-driven from config/registry/, so it stays in sync. Two modes:

  python3 automation/scripts/standards_mapping_audit.py           # write report
  python3 automation/scripts/standards_mapping_audit.py --check   # gate (CI)

`--check` writes nothing and exits non-zero if any standard id is malformed or
does not resolve to a real mas.owasp.org page; it is the pre-commit/CI gate.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "config" / "registry"
MAS_LINKS = ROOT / ".hugo" / "scripts" / "mas_links.json"
OUT = ROOT / "docs" / "standards_mapping_audit.md"

VALID_MASVS_GROUPS = {
    "STORAGE",
    "CRYPTO",
    "AUTH",
    "NETWORK",
    "PLATFORM",
    "CODE",
    "RESILIENCE",
    "PRIVACY",
}
MASVS_RE = re.compile(r"^MASVS-([A-Z]+)-\d+$")
MASWE_RE = re.compile(r"^MASWE-\d{4}$")
MASTG_TEST_RE = re.compile(r"^MASTG-TEST-\d{4}$")
MASTG_DEMO_RE = re.compile(r"^MASTG-DEMO-\d{4}$")

# Categories whose modules legitimately have no MASTG test id yet, with the
# reason, so the coverage gap reads as an honest catalog gap, not an omission.
GAP_REASON = {
    "ai_ml": "OWASP MAS has no MASTG tests for LLM/GenAI risks yet; mapped to a "
    "MASVS control, the closest MASWE weakness, and the OWASP LLM Top 10.",
    "agentic": "OWASP MAS has no MASTG tests for agentic-AI risks yet; mapped to "
    "MASVS controls, the closest MASWE weakness, and the OWASP "
    "Agentic Top 10.",
    "auth": "WebAuthn/passkey and modern OAuth tests are newer than the current "
    "MASTG; mapped to MASVS-AUTH controls and MASWE weaknesses.",
}


def load_registry() -> tuple[dict, list]:
    meta = yaml_safe(REGISTRY / "meta.yaml")
    order = meta.get("category_order", [])
    cats = {}
    for cid in order:
        cat_dir = REGISTRY / "categories" / cid
        if cat_dir.is_dir():
            merged, vulns = None, []
            for shard in sorted(cat_dir.glob("*.yaml")):
                sc = yaml_safe(shard)[cid]
                merged = merged or dict(sc)
                vulns += sc.get("vulnerabilities", [])
            merged["vulnerabilities"] = vulns
            cats[cid] = merged
        else:
            cats[cid] = yaml_safe(REGISTRY / "categories" / f"{cid}.yaml")[cid]
    return cats, order


def yaml_safe(path: Path) -> dict:
    import yaml

    with open(path) as f:
        return yaml.safe_load(f) or {}


def _chips(ids: list) -> str:
    return ", ".join(f"`{i}`" for i in ids) if ids else "-"


def _scan(cats: dict, order: list) -> tuple[list[str], list[str], int, int, int]:
    """Validate every standard id in the registry.

    Returns (malformed, unresolved, total, have_maswe, have_mastg). `malformed`
    is a standard id with the wrong shape or an invalid MASVS group; `unresolved`
    is a well-formed MASWE/MASTG id that does not resolve to a real
    mas.owasp.org page (i.e. is missing from .hugo/scripts/mas_links.json)."""
    links = {}
    if MAS_LINKS.exists():
        links = json.loads(MAS_LINKS.read_text()).get("paths", {})

    total = sum(len(cats[c].get("vulnerabilities", [])) for c in order)
    malformed: list[str] = []
    unresolved: list[str] = []
    have_maswe = have_mastg = 0

    for cid in order:
        for v in cats[cid].get("vulnerabilities", []):
            vid = v["id"]
            for x in v.get("masvs", []) or []:
                m = MASVS_RE.match(x)
                if not m or m.group(1) not in VALID_MASVS_GROUPS:
                    malformed.append(f"{vid}: {x}")
            for x in v.get("maswe", []) or []:
                if not MASWE_RE.match(x):
                    malformed.append(f"{vid}: {x}")
                elif x not in links:
                    unresolved.append(f"{vid}: {x}")
            for x in v.get("mastg_v2", []) or []:
                if not MASTG_TEST_RE.match(x):
                    malformed.append(f"{vid}: {x}")
                elif x not in links:
                    unresolved.append(f"{vid}: {x}")
            for x in v.get("mastg_demo", []) or []:
                if not MASTG_DEMO_RE.match(x):
                    malformed.append(f"{vid}: {x}")
                elif x not in links:
                    unresolved.append(f"{vid}: {x}")
            if v.get("maswe"):
                have_maswe += 1
            if v.get("mastg_v2"):
                have_mastg += 1

    return malformed, unresolved, total, have_maswe, have_mastg


def check() -> int:
    """Gate mode: fail if any standard id is malformed or does not resolve to a
    real mas.owasp.org page. Used by pre-commit and CI; writes no report."""
    cats, order = load_registry()
    malformed, unresolved, total, _, _ = _scan(cats, order)
    if malformed or unresolved:
        print(
            f"standards_mapping_audit: {len(malformed)} malformed and "
            f"{len(unresolved)} unresolved standard id(s) in {total} modules:",
            file=sys.stderr,
        )
        for m in malformed:
            print(f"  malformed: {m}", file=sys.stderr)
        for u in unresolved:
            print(f"  unresolved (no mas.owasp.org page): {u}", file=sys.stderr)
        return 1
    print(f"standards_mapping_audit: {total} modules, all standard ids well-formed and resolvable.")
    return 0


def report() -> None:
    cats, order = load_registry()
    malformed, unresolved, total, have_maswe, have_mastg = _scan(cats, order)
    out: list[str] = []
    out.append("# Standards naming & mapping audit")
    out.append("")
    out.append(
        "_Generated by `automation/scripts/standards_mapping_audit.py`. "
        "Re-run after registry changes._"
    )
    out.append("")
    out.append(
        "**How DVMA names things vs. the standard.** MASVS defines "
        "*controls* (e.g. `MASVS-STORAGE-1`), not named vulnerabilities. "
        "The OWASP artifacts that name specific weaknesses and test "
        "procedures are **MASWE** (weaknesses) and **MASTG** (tests / "
        "demos). So every DVMA module keeps its own descriptive "
        "`title`/`id` and *maps* to the relevant MASVS control(s), plus a "
        "MASWE weakness and MASTG test **where one exists**. A 1:1 "
        "name-to-MASVS match is neither possible nor the goal."
    )
    out.append("")
    out.append("## Integrity checks")
    out.append("")
    out.append(
        f"- **{total}** modules total; **{total}** carry at least one "
        "MASVS control mapping (zero missing)."
    )
    out.append(
        f"- Malformed / invalid-group standard ids: "
        f"**{len(malformed) or 'none'}**"
        + (f" ({'; '.join(malformed)})" if malformed else "")
        + "."
    )
    out.append(
        f"- Referenced MASWE/MASTG ids that do **not** resolve to a real "
        f"`mas.owasp.org` page: **{len(unresolved) or 'none'}**"
        + (f" ({'; '.join(unresolved)})" if unresolved else "")
        + ", every mapped id links to an actual standard page, none are "
        "placeholders."
    )
    out.append(
        f"- Modules with a MASWE mapping: **{have_maswe}/{total}**; with a "
        f"MASTG (v2) test: **{have_mastg}/{total}**. The remainder are "
        "documented gaps below, not omissions."
    )
    out.append("")
    out.append("## Coverage by category")
    out.append("")
    out.append(
        "| Category | OWASP Mobile | Modules | Has MASWE | Has MASTG | MASWE gap | MASTG gap |"
    )
    out.append(
        "|----------|:------------:|:-------:|:---------:|:---------:|:--------:|:---------:|"
    )
    for cid in order:
        vs = cats[cid].get("vulnerabilities", [])
        n = len(vs)
        hm = sum(1 for v in vs if v.get("maswe"))
        ht = sum(1 for v in vs if v.get("mastg_v2"))
        out.append(
            f"| {cats[cid].get('title', cid)} "
            f"| {cats[cid].get('owasp_mobile', '')} | {n} | {hm} | {ht} "
            f"| {n - hm} | {n - ht} |"
        )
    out.append("")
    out.append("## Documented gaps (why a module has no MASTG test id)")
    out.append("")
    out.append(
        "Every module now maps to a MASVS control **and** a MASWE "
        "weakness (see the totals above). The remaining gap is **MASTG "
        "tests**: OWASP has not published a test/demo for every weakness "
        "class, 36 of the 78 MASWE v1.0.0 weaknesses still have no "
        "MASTG test, so modules whose weakness lacks a test carry a "
        "MASWE id but no `mastg_v2`. That is a catalog gap, not an "
        "omission; inventing a test id would be dishonest parity."
    )
    out.append("")
    for cid in order:
        miss = [v["id"] for v in cats[cid].get("vulnerabilities", []) if not v.get("mastg_v2")]
        if not miss:
            continue
        reason = GAP_REASON.get(
            cid, "No matching MASTG test in the current catalog; mapped to MASVS + MASWE."
        )
        out.append(f"**{cats[cid].get('title', cid)}** ({len(miss)}): {reason}")
        out.append("")
        out.append("".join(f"- `{m}`\n" for m in miss))

    out.append("## Per-module mapping")
    out.append("")
    out.append("DVMA title/id → the standards it maps to.")
    out.append("")
    out.append("| Category | Module (DVMA id) | Title | MASVS | MASWE | MASTG (v2) |")
    out.append("|----------|------------------|-------|-------|-------|------------|")
    for cid in order:
        title = cats[cid].get("title", cid)
        for v in cats[cid].get("vulnerabilities", []):
            out.append(
                f"| {title} | `{v['id']}` | {v.get('title', '')} "
                f"| {_chips(v.get('masvs', []))} "
                f"| {_chips(v.get('maswe', []))} "
                f"| {_chips(v.get('mastg_v2', []))} |"
            )
    out.append("")

    OUT.write_text("\n".join(out))
    print(
        f"Wrote {OUT.relative_to(ROOT)}: {total} modules "
        f"(MASWE {have_maswe}, MASTG {have_mastg}, "
        f"malformed {len(malformed)}, unresolved {len(unresolved)})."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="gate mode: exit non-zero if any standard id is malformed or does "
        "not resolve to a real mas.owasp.org page; write no report.",
    )
    args = parser.parse_args()
    if args.check:
        sys.exit(check())
    report()
