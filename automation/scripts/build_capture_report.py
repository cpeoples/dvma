#!/usr/bin/env python3
"""Assemble the DVMA capture report from harness outputs.

Reads:
  * logcat evidence lines (tag DVMA-EVIDENCE), one per real artifact recorded,
  * pulled per-module sink files (automation/artifacts/files/<vulnId>.txt),
  * pulled shared_prefs XML + SQLite db files,
  * network flows captured by capture_listener.py (JSONL).

Writes a single Markdown report correlating, per module, exactly what real
artifact was observed on-device / on-the-wire.

FOR AUTHORIZED TRAINING USE ONLY.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

_EVIDENCE_LINE = re.compile(r"\[(?P<vuln>[a-z0-9_]+)\]\s+(?P<kind>[\w-]+)\s+::\s+(?P<art>.*)")


def _parse_logcat(path: str) -> dict[str, list[tuple[str, str]]]:
    hits: dict[str, list[tuple[str, str]]] = defaultdict(list)
    p = Path(path)
    if not p.exists():
        return hits
    with p.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = _EVIDENCE_LINE.search(line)
            if m:
                hits[m.group("vuln")].append((m.group("kind"), m.group("art").strip()))
    return hits


def _read_sink_files(files_dir: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in sorted(Path(files_dir).glob("*.txt")):
        out[p.stem] = p.read_text(encoding="utf-8", errors="replace").strip()
    return out


# Artifact files are appended blocks of: "<iso-ts>\t<kind>\n<artifact...>\n\n".
_ARTIFACT_BLOCK = re.compile(
    r"^\S+\t(?P<kind>[\w-]+)\n(?P<art>.*?)(?=\n\S+\t[\w-]+\n|\Z)",
    re.MULTILINE | re.DOTALL,
)


def _kinds_from_file(text: str) -> list[tuple[str, str]]:
    """Extract (kind, first-line-of-artifact) pairs from a pulled artifact file
    so file-only modules (no logcat) still get structured bullets."""
    pairs: list[tuple[str, str]] = []
    for m in _ARTIFACT_BLOCK.finditer(text):
        art = m.group("art").strip()
        first = art.splitlines()[0] if art else ""
        pairs.append((m.group("kind"), first))
    return pairs


def _read_flows(path: str) -> list[dict]:
    flows: list[dict] = []
    p = Path(path)
    if not p.exists():
        return flows
    with p.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    flows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return flows


def _list_state(artifacts: str, sub: str) -> list[str]:
    d = Path(artifacts) / sub
    if not d.is_dir():
        return []
    return sorted(p.name for p in d.iterdir() if p.is_file())


def _read_attacker(log_path: str | None, artifacts: str) -> list[str]:
    """Lines the companion attacker app harvested across the process boundary,
    from its logcat (tag DVMA-ATTACKER) and its pulled capture file."""
    out: list[str] = []
    if log_path and Path(log_path).exists():
        with Path(log_path).open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                idx = line.find("HARVESTED")
                if idx != -1:
                    out.append(line[idx:].strip())
    cap = Path(artifacts) / "attacker" / "attacker_captures.txt"
    if cap.exists():
        with cap.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(line.split("\t", 1)[-1])
    # De-dupe while preserving order.
    seen: set[str] = set()
    return [x for x in out if not (x in seen or seen.add(x))]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", required=True)
    ap.add_argument("--logcat", required=True)
    ap.add_argument("--flows", required=True)
    ap.add_argument("--attacker-log", default=None)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    logcat = _parse_logcat(args.logcat)
    sink = _read_sink_files(str(Path(args.artifacts) / "files"))
    flows = _read_flows(args.flows)
    attacker = _read_attacker(args.attacker_log, args.artifacts)
    prefs = _list_state(args.artifacts, "prefs")
    dbs = _list_state(args.artifacts, "databases")

    modules = sorted(set(logcat) | set(sink))

    lines: list[str] = []
    lines.append("# DVMA capture report\n")
    lines.append(
        "_Real artifacts observed while walking every module. "
        "FOR AUTHORIZED TRAINING USE ONLY._\n"
    )
    lines.append("## Summary\n")
    lines.append(f"- Modules that emitted a real evidence artifact: **{len(modules)}**")
    lines.append(f"- Network flows captured by the listener: **{len(flows)}**")
    lines.append(
        f"- shared_prefs files pulled: **{len(prefs)}** " f"({', '.join(prefs) or 'none'})"
    )
    lines.append(f"- SQLite databases pulled: **{len(dbs)}** " f"({', '.join(dbs) or 'none'})")
    lines.append(f"- Cross-app captures by companion attacker app: " f"**{len(attacker)}**\n")

    lines.append("## Per-module evidence\n")
    if not modules:
        lines.append(
            "_No DVMA-EVIDENCE lines captured. Was the app built with "
            "the real modules and walked with `-PdvmaAndroidTest=true`?_\n"
        )
    for vuln in modules:
        lines.append(f"### `{vuln}`\n")
        seen_bullets = set()
        for kind, art in logcat.get(vuln, []):
            bullet = f"- **{kind}** (logcat): `{art}`"
            if bullet not in seen_bullets:
                lines.append(bullet)
                seen_bullets.add(bullet)
        if vuln in sink:
            for kind, first in _kinds_from_file(sink[vuln]):
                bullet = f"- **{kind}** (artifact): `{first}`"
                if bullet not in seen_bullets:
                    lines.append(bullet)
                    seen_bullets.add(bullet)
            lines.append("\n<details><summary>pulled artifact file</summary>\n")
            lines.append("```")
            lines.append(sink[vuln])
            lines.append("```")
            lines.append("</details>\n")
        lines.append("")

    if flows:
        lines.append("## Captured network flows\n")
        for fl in flows:
            lines.append(
                f"- `{fl.get('scheme')}` **{fl.get('method')}** "
                f"`{fl.get('path')}` from {fl.get('client')} "
                f"@ {fl.get('ts')}"
            )
            body = (fl.get("body") or "").strip()
            if body:
                lines.append(f"  - body: `{body[:300]}`")
        lines.append("")

    if attacker:
        lines.append("## Cross-app captures (companion attacker app)\n")
        lines.append(
            "_Harvested by the separate, unprivileged `com.dvma.attacker` "
            "app across an Android process/trust boundary - the "
            "leak is cross-app, not an in-process simulation._\n"
        )
        for line in attacker:
            lines.append(f"- `{line}`")
        lines.append("")

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"[report] wrote {args.out} ({len(modules)} modules, {len(flows)} flows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
