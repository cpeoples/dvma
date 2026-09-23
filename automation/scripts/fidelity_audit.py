#!/usr/bin/env python3
"""
fidelity_audit.py, senior-researcher fidelity verdict for every DVMA module.

FOR AUTHORIZED SECURITY-TRAINING USE ONLY.

Unlike inspect_modules.py (which credits any DvmaEvidence.record call as
"real"), this classifier asks the question a mobile security researcher asks:
"if I attach a proxy / logcat / drozer / frida and run this, does a *real*
side effect happen that my tooling observes, or is it a narrated slide?"

For each module it reads the screen + sibling dart, follows the shared helpers
it imports (native bridges, passkey store, webview host, evidence sink), and
assigns ONE verdict:

  REAL-IO       real disk / db / network / clipboard / process side effect
                observable off-device (file pull, packet, SQLite row).
  REAL-NATIVE   drives a real Android/iOS component or platform-channel probe
                whose native handler performs an OS side effect.
  REAL-CRYPTO   performs genuine crypto (real weak/strong primitive) whose
                output is the exploit (predictable token, forgeable MAC, ...).
  REAL-LOGIC    no external artifact, but the vulnerability *is* the decision
                logic and exercising it is a faithful exploit (authz bypass,
                prompt injection, oauth/redirect/session flaws). Legitimate.
  NARRATION     only setState + a DvmaEvidence.record that *describes* a leak
                that never mechanically happened. The scoff set.

Output: automation/artifacts/fidelity_audit.md + .json
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MANIFEST = REPO / "automation" / "vuln_manifest.json"
MODULES_ROOT = REPO / "lib" / "modules"
CORE = REPO / "lib" / "core"
ART = REPO / "automation" / "artifacts"

# Shared helpers whose own code performs a real side effect; a module that
# calls into one inherits that helper's fidelity tier.
HELPERS = {
    "provider_ipc_bridge": ("ProviderIpcBridge", "REAL-NATIVE"),
    "platform_ipc_bridge": ("PlatformIpcBridge", "REAL-NATIVE"),
    "broadcast_ipc_bridge": ("BroadcastIpcBridge", "REAL-NATIVE"),
    "component_ipc_bridge": ("ComponentIpcBridge", "REAL-NATIVE"),
    "app_group_bridge": ("AppGroupBridge", "REAL-NATIVE"),
    "resilience_bridge": ("ResilienceBridge", "REAL-NATIVE"),
    "system_provider_bridge": ("SystemProviderBridge", "REAL-NATIVE"),
    "webview_demo_host": ("WebViewDemoHost", "REAL-NATIVE"),
    "passkey_ceremony": ("PasskeyEvidenceStore", "REAL-CRYPTO"),
    # The AI/ML mock LLM makes a real keyless http.post to a live model
    # (Pollinations/OpenRouter) with an unguarded system prompt, so any module
    # that drives it through .complete() is a real network exploit, not narration.
    "mock_llm": ("MockLlm", "REAL-IO"),
}

# Mechanism regexes, most-specific first. Each maps to a verdict tier.
REAL_IO = re.compile(
    r"writeAsString|writeAsBytes|\.openWrite|IOSink"
    r"|openDatabase|rawInsert|rawQuery|\bdb\.(insert|execute|update|delete)"
    r"|\.(get|post|put|delete|read)\s*\(\s*(uri|Uri|url|_url|endpoint)"
    r"|http\.(get|post|put|delete|read)|HttpClient|Socket\.connect|\.getUrl"
    r"|SharedPreferences|\.set(String|Int|Bool|Double|StringList)\s*\("
    r"|FlutterSecureStorage|\.write\s*\(\s*key:"
    r"|developer\.log|\bprint\s*\("
    r"|Clipboard\.setData|Process\.(run|start)"
    r"|getTemporaryDirectory|getExternalStorageDirectory|getApplicationDocumentsDirectory"
    r"|writableBaseDir"
)
REAL_CRYPTO = re.compile(
    r"\bRandom\s*\(|Random\.secure|pointycastle|package:crypto"
    r"|Hmac\s*\(|sha256\b|sha1\b|md5\b|AesCbc|AesGcm|Cipher|PBKDF2|pbkdf2"
    r"|encrypt\s*\(|RSASigner|SHA256Digest"
)
REAL_NATIVE = re.compile(
    r"MethodChannel\s*\(|invokeMethod\s*\(|EventChannel\s*\("
    r"|AndroidIntent|startActivity|launchUrl\s*\("
    r"|WebViewController|loadRequest\s*\(|loadHtmlString\s*\(|runJavaScript"
    r"|LocalAuthentication|BiometricPrompt|local_auth"
)
# Real-logic markers: the module clearly runs an exploit decision path.
REAL_LOGIC = re.compile(
    r"\bif\s*\(|switch\s*\(|\.contains\(|RegExp\(|jsonDecode|jsonEncode"
    r"|base64|utf8\.(en|de)code|Uri\.parse|\.split\(|\.where\(|\.map\("
)
NARRATION_RECORD = re.compile(r"DvmaEvidence\.record\s*\(")


def load_manifest():
    return json.load(open(MANIFEST))["modules"]


def helper_blob_cache():
    cache = {}
    for stem, (cls, tier) in HELPERS.items():
        for base in (CORE, CORE / "native", MODULES_ROOT / "auth", MODULES_ROOT / "ai_ml"):
            f = base / f"{stem}.dart"
            if f.is_file():
                cache[stem] = (cls, tier, f.read_text())
                break
    return cache


def module_dart(cat, mid):
    d = MODULES_ROOT / cat / mid
    if not d.is_dir():
        return "", []
    files = sorted(d.glob("*.dart"))
    return "\n".join(f.read_text() for f in files), [f.relative_to(REPO).as_posix() for f in files]


def classify(blob: str, helpers):
    reasons = []
    # Helper inheritance first (native bridges / passkey / webview host).
    for stem, (cls, tier) in HELPERS.items():
        if re.search(rf"\b{cls}\b", blob):
            reasons.append(f"uses {cls} ({tier})")
            return tier, reasons
    if REAL_IO.search(blob):
        return "REAL-IO", ["real disk/db/network/clipboard/process I/O"]
    if REAL_NATIVE.search(blob):
        return "REAL-NATIVE", ["real native/platform-channel/webview/intent effect"]
    if REAL_CRYPTO.search(blob):
        return "REAL-CRYPTO", ["real crypto primitive computed"]
    # Distinguish real-logic from narration: does the module do meaningful
    # computation, or does it only setState + record a described leak?
    has_record = bool(NARRATION_RECORD.search(blob))
    # Strip the record() call bodies so their string args don't inflate logic.
    body_wo_records = re.sub(r"DvmaEvidence\.record\s*\([^;]*\);", "", blob, flags=re.S)
    logic_in_body = len(REAL_LOGIC.findall(body_wo_records))
    if logic_in_body >= 6:
        return "REAL-LOGIC", [f"substantive decision logic ({logic_in_body} markers)"]
    if has_record and logic_in_body < 6:
        return "NARRATION", [f"only setState + record; thin logic ({logic_in_body} markers)"]
    return "REAL-LOGIC", [f"logic ({logic_in_body} markers)"]


def main():
    modules = load_manifest()
    helpers = helper_blob_cache()
    results = []
    for m in modules:
        cat, mid = m["category"], m["id"]
        blob, files = module_dart(cat, mid)
        verdict, reasons = classify(blob, helpers)
        results.append(
            {
                "id": mid,
                "category": cat,
                "title": m.get("title", ""),
                "platforms": m.get("platforms", []),
                "verdict": verdict,
                "reasons": reasons,
                "files": files,
            }
        )

    ORDER = ["REAL-IO", "REAL-NATIVE", "REAL-CRYPTO", "REAL-LOGIC", "NARRATION"]
    by_v = Counter(r["verdict"] for r in results)
    by_cat = defaultdict(Counter)
    for r in results:
        by_cat[r["category"]][r["verdict"]] += 1

    L = [
        "# DVMA fidelity audit, senior-researcher lens\n",
        "Verdict per module: does real tooling (proxy / logcat / drozer / "
        "frida / file pull) observe a genuine effect, or is it narrated?\n",
        "- **REAL-IO / REAL-NATIVE / REAL-CRYPTO**, a researcher sees a real "
        "artifact/effect. No scoffing.",
        "- **REAL-LOGIC**, no external artifact, but the exploit *is* the "
        "decision path (authz bypass, prompt injection, oauth). Legitimate.",
        "- **NARRATION**, only prints/records a described leak. **The set to "
        "upgrade or remove.**\n",
        f"Total: **{len(results)}**",
    ]
    for v in ORDER:
        L.append(f"- {v}: **{by_v.get(v, 0)}**")
    L.append("\n## By category\n")
    L.append("| category | REAL-IO | REAL-NATIVE | REAL-CRYPTO | REAL-LOGIC | NARRATION |")
    L.append("|---|--:|--:|--:|--:|--:|")
    for c in sorted(by_cat):
        x = by_cat[c]
        L.append(
            f"| {c} | {x.get('REAL-IO',0)} | {x.get('REAL-NATIVE',0)} | "
            f"{x.get('REAL-CRYPTO',0)} | {x.get('REAL-LOGIC',0)} | "
            f"{x.get('NARRATION',0)} |"
        )

    narr = [r for r in results if r["verdict"] == "NARRATION"]
    L.append(f"\n## NARRATION, upgrade or remove ({len(narr)})\n")
    L.append("| id | category | platforms | why flagged |")
    L.append("|---|---|---|---|")
    for r in sorted(narr, key=lambda x: (x["category"], x["id"])):
        L.append(
            f"| {r['id']} | {r['category']} | "
            f"{','.join(r['platforms']) or 'both'} | {'; '.join(r['reasons'])} |"
        )

    L.append("\n## All modules\n")
    for r in sorted(results, key=lambda x: (ORDER.index(x["verdict"]), x["category"], x["id"])):
        L.append(f"- `{r['verdict']}` **{r['id']}** ({r['category']}), {'; '.join(r['reasons'])}")

    ART.mkdir(parents=True, exist_ok=True)
    (ART / "fidelity_audit.md").write_text("\n".join(L) + "\n")
    json.dump({"modules": results}, open(ART / "fidelity_audit.json", "w"), indent=2)

    print(f"audited {len(results)} modules")
    for v in ORDER:
        print(f"  {v:12s}: {by_v.get(v,0)}")
    print(f"NARRATION set: {[r['id'] for r in narr]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
