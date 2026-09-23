#!/usr/bin/env python3
"""
inspect_modules.py - static fidelity inspection of every DVMA module.

FOR AUTHORIZED SECURITY-TRAINING USE ONLY.

Goal: for each module in automation/vuln_manifest.json, read its Dart screen
(lib/modules/<category>/<id>/<id>_screen.dart) and any sibling files in the
module dir, then detect what *real-world* side effects it performs so we can
tell a genuinely-exploitable module from one that only *simulates* the vuln in
the UI.

It does NOT run anything on a device. It classifies statically:
  REAL       - performs a concrete insecure side effect (disk/db/net/crypto/
               platform-channel/clipboard/...) AND/OR mirrors an artifact via
               DvmaEvidence.record.
  SIMULATED  - shows an EvidencePanel / sets state but no detectable real I/O
               and no evidence record  -> needs manual review, may be fake.
  UNCLEAR    - has some signal but ambiguous; flag for human eyes.

Output:
  - automation/artifacts/module_inspection.json   (structured, per module)
  - automation/artifacts/module_inspection.md      (human report, by category)

Usage:
  python3 automation/scripts/inspect_modules.py
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MANIFEST = REPO / "automation" / "vuln_manifest.json"
MODULES_ROOT = REPO / "lib" / "modules"
ART = REPO / "automation" / "artifacts"

# Real-world side-effect signals.
# Each signal maps a label -> regex. Presence means the module actually touches
# that surface (not just talks about it). Kept conservative to avoid false
# "REAL" claims: we look for the *call*, not a comment.
#
# ARTIFACT signals: produce a DEVICE-EXTRACTABLE artifact (adb-pullable file,
# SQLite row, outbound request, logcat line via DvmaEvidence). This is the
# DVIA/DVWA bar the user set: REAL-ARTIFACT.
# Shared helper files (outside a module's own dir) that are themselves
# real-artifact: if a module imports/uses one, the module inherits that artifact.
# Maps a helper-call regex -> the artifact "kind" it effectively produces. This
# keeps the audit honest (the helper's own code performs the real I/O) while
# crediting modules that centralize their real side effect in a shared class.
HELPER_ARTIFACT_SIGNALS = {
    # Passkey suite: PasskeyEvidenceStore.persist() writes real SharedPreferences
    # AND calls DvmaEvidence.record internally (see lib/modules/auth/passkey_ceremony.dart).
    "passkey_store": r"PasskeyEvidenceStore\.(persist|read)\s*\(",
    # Native bridges: each invokes a MethodChannel whose Kotlin handler performs a
    # real OS side effect and records via the DVMA-EVIDENCE logcat tag / files dir.
    "provider_bridge": r"ProviderIpcBridge|provider_ipc",
    "platform_bridge": r"PlatformIpcBridge|platform_ipc",
    "resilience_bridge": r"ResilienceBridge|resilience_bridge|dvma/resilience",
    "sysprovider_bridge": r"SystemProviderBridge|system_provider",
    "webview_host": r"WebViewDemoHost|webview_demo_host",
}

ARTIFACT_SIGNALS = {
    "evidence_record": r"DvmaEvidence\.record\s*\(",
    "prefs_write": r"\.set(String|Int|Bool|Double|StringList)\s*\(",
    "file_write": r"\.writeAsString\s*\(|\.writeAsBytes\s*\(|IOSink|openWrite\s*\(",
    "sqlite": r"openDatabase\s*\(|rawInsert\s*\(|rawQuery\s*\(|\bdb\.(insert|execute|rawQuery)\s*\(",
    "network_http": r"HttpClient\s*\(|http\.(get|post|put|delete)\s*\(|Dio\(|\.getUrl\s*\(|Socket\.connect",
    "clipboard": r"Clipboard\.setData\s*\(",
    "external_dir": r"getExternalStorageDirectory|getApplicationDocumentsDirectory|getTemporaryDirectory",
    "process_exec": r"Process\.(run|start)\s*\(",
    **HELPER_ARTIFACT_SIGNALS,
}

# BEHAVIOR signals: real exploitable logic/UI/native effect that is observable
# but may not drop a pullable artifact (native channel side effects, intent
# launches, webview loads, biometric gates, crypto ops). REAL-BEHAVIOR.
BEHAVIOR_SIGNALS = {
    "platform_channel": r"MethodChannel\s*\(|invokeMethod\s*\(|EventChannel\s*\(",
    "crypto": r"\bencrypt\s*\(|\bdecrypt\s*\(|AES|Cipher|Hmac|\bsha1\b|\bmd5\b",
    "intent_launch": r"AndroidIntent|launchUrl\s*\(|startActivity",
    "webview": r"WebViewController|loadRequest\s*\(|loadHtmlString\s*\(|runJavaScript",
    "biometric": r"LocalAuthentication|BiometricPrompt|\bauthenticate\s*\(",
    "prefs_read": r"SharedPreferences\.getInstance",
}

# Legacy combined map kept for the signal listing in output.
SIGNALS = {**ARTIFACT_SIGNALS, **BEHAVIOR_SIGNALS}

# UI-only signals: presence of these WITHOUT any real signal above => suspicious
UI_ONLY = {
    "evidence_panel": r"EvidencePanel\s*\(",
    "setstate": r"setState\s*\(",
    "demo_action": r"DemoActionButton\s*\(",
}

# Signals that a module is intentionally native-backed (the Dart just bridges):
NATIVE_HINT = r"MethodChannel|invokeMethod|com\.dvma|am start|Intent"


def load_manifest():
    with open(MANIFEST) as f:
        return json.load(f)["modules"]


def module_files(category: str, mid: str):
    """Return list of dart files for a module (screen + siblings)."""
    d = MODULES_ROOT / category / mid
    if not d.is_dir():
        return []
    return [d / name for name in sorted(p.name for p in d.iterdir()) if name.endswith(".dart")]


def extract_explanation(text: str) -> str:
    """Pull the authored `explanation:` string (teaching text) if present."""
    m = re.search(r"explanation:\s*((?:'[^']*'\s*)+)", text)
    if not m:
        return ""
    parts = re.findall(r"'([^']*)'", m.group(1))
    return " ".join(p.strip() for p in parts).strip()


def extract_records(text: str):
    """Extract (kind, artifact-ish) hints from DvmaEvidence.record(id, kind, ...)."""
    records = []
    for m in re.finditer(r"DvmaEvidence\.record\s*\(", text):
        tail = text[m.end() : m.end() + 400]
        # second string literal after the id arg is the `kind`
        strs = re.findall(r"'([^']*)'", tail)
        kind = strs[1] if len(strs) >= 2 else (strs[0] if strs else "")
        records.append(kind)
    return records


def extract_title(text: str) -> str:
    m = re.search(r"title:\s*'([^']*)'", text)
    return m.group(1) if m else ""


def classify(signals: dict, records: list, ui: dict) -> str:
    artifact = [k for k in ARTIFACT_SIGNALS if signals.get(k)]
    behavior = [k for k in BEHAVIOR_SIGNALS if signals.get(k)]
    if records or artifact:
        return "REAL-ARTIFACT"
    if behavior:
        return "REAL-BEHAVIOR"
    if ui.get("evidence_panel") or ui.get("demo_action"):
        return "MODELED"
    return "UNCLEAR"


def main():
    modules = load_manifest()
    results = []
    for m in modules:
        mid = m["id"]
        cat = m["category"]
        files = module_files(cat, mid)
        blob = ""
        for fp in files:
            try:
                blob += "\n" + fp.read_text(encoding="utf-8")
            except OSError:
                pass

        signals = {name: bool(re.search(rx, blob)) for name, rx in SIGNALS.items()}
        ui = {name: bool(re.search(rx, blob)) for name, rx in UI_ONLY.items()}
        records = extract_records(blob)
        explanation = extract_explanation(blob)
        native = bool(re.search(NATIVE_HINT, blob))
        verdict = classify(signals, records, ui)

        results.append(
            {
                "id": mid,
                "category": cat,
                "title": m.get("title") or extract_title(blob),
                "platforms": m.get("platforms", []),
                "files": [f.relative_to(REPO).as_posix() for f in files],
                "verdict": verdict,
                "artifact_signals": [k for k in ARTIFACT_SIGNALS if signals.get(k)],
                "behavior_signals": [k for k in BEHAVIOR_SIGNALS if signals.get(k)],
                "evidence_records": records,
                "native_backed": native,
                "explanation": explanation,
            }
        )

    ART.mkdir(parents=True, exist_ok=True)
    with open(ART / "module_inspection.json", "w") as f:
        json.dump({"modules": results}, f, indent=2)

    # ---- human report ----
    ORDER = ["REAL-ARTIFACT", "REAL-BEHAVIOR", "MODELED", "UNCLEAR"]
    by_verdict = Counter(r["verdict"] for r in results)
    by_cat = defaultdict(Counter)
    for r in results:
        by_cat[r["category"]][r["verdict"]] += 1

    lines = []
    lines.append("# DVMA module fidelity inspection\n")
    lines.append(
        "Static analysis of what each module *actually does* on a real "
        "device. Bar for this training app = **REAL-ARTIFACT** "
        "(device-extractable proof, DVIA/DVWA parity).\n"
    )
    lines.append(
        "- **REAL-ARTIFACT** - drops an adb-pullable file / SQLite row / "
        "outbound request / logcat artifact (via DvmaEvidence.record)."
    )
    lines.append(
        "- **REAL-BEHAVIOR** - genuine exploitable logic/UI/native effect, "
        "observable in-app, but no external artifact yet."
    )
    lines.append(
        "- **MODELED** - vuln only simulated in pure Dart (e.g. in-memory "
        "map standing in for the Keychain); real attacker tooling finds "
        "nothing on-device. **These are the fidelity gaps.**"
    )
    lines.append("- **UNCLEAR** - ambiguous; needs eyes.\n")
    lines.append(f"- Total modules: **{len(results)}**")
    for v in ORDER:
        lines.append(f"- {v}: **{by_verdict.get(v, 0)}**")
    lines.append("\n## By category\n")
    lines.append("| category | REAL-ARTIFACT | REAL-BEHAVIOR | MODELED | UNCLEAR |")
    lines.append("|---|---:|---:|---:|---:|")
    for cat in sorted(by_cat):
        c = by_cat[cat]
        lines.append(
            f"| {cat} | {c.get('REAL-ARTIFACT', 0)} | "
            f"{c.get('REAL-BEHAVIOR', 0)} | {c.get('MODELED', 0)} | "
            f"{c.get('UNCLEAR', 0)} |"
        )

    # Highlight the ones below the bar first (everything not REAL-ARTIFACT).
    flagged = [r for r in results if r["verdict"] != "REAL-ARTIFACT"]
    lines.append(f"\n## Below REAL-ARTIFACT bar - review/upgrade ({len(flagged)})\n")
    if not flagged:
        lines.append("_None - every module drops a device-extractable artifact._\n")
    else:
        lines.append("| id | category | verdict | native? | behavior signals |")
        lines.append("|---|---|---|---|---|")
        for r in sorted(flagged, key=lambda x: (ORDER.index(x["verdict"]), x["category"], x["id"])):
            bsig = ", ".join(r["behavior_signals"]) or "-"
            lines.append(
                f"| {r['id']} | {r['category']} | {r['verdict']} | "
                f"{'yes' if r['native_backed'] else 'no'} | {bsig} |"
            )

    lines.append("\n## All modules (detail)\n")
    for r in sorted(results, key=lambda x: (x["category"], x["id"])):
        asig = ", ".join(r["artifact_signals"]) or "-"
        bsig = ", ".join(r["behavior_signals"]) or "-"
        recs = ", ".join(r["evidence_records"]) or "-"
        lines.append(f"### {r['id']}  ·  `{r['verdict']}`")
        lines.append(f"- category: {r['category']}  ·  platforms: {', '.join(r['platforms'])}")
        lines.append(f"- artifact signals: {asig}")
        lines.append(f"- behavior signals: {bsig}")
        lines.append(f"- evidence.record kinds: {recs}")
        if r["explanation"]:
            lines.append(f"- explanation: {r['explanation']}")
        lines.append("")

    with open(ART / "module_inspection.md", "w") as f:
        f.write("\n".join(lines))

    # console summary
    print(f"inspected {len(results)} modules")
    for v in ORDER:
        print(f"  {v:14s}: {by_verdict.get(v, 0)}")
    print("report: automation/artifacts/module_inspection.md")
    print("json  : automation/artifacts/module_inspection.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
