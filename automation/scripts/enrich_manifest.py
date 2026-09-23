#!/usr/bin/env python3
"""
enrich_manifest.py - fold per-module evidence descriptions into vuln_manifest.json.

FOR AUTHORIZED SECURITY-TRAINING USE ONLY.

Reads automation/artifacts/module_inspection.json (the fidelity inspection) and
adds an `evidence` block to every module in automation/vuln_manifest.json so the
manifest itself documents, for each vuln, WHAT real artifact it produces and HOW
to extract it on-device. Idempotent: rerun after any re-inspection.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MANIFEST = REPO / "automation" / "vuln_manifest.json"
INSPECT = REPO / "automation" / "artifacts" / "module_inspection.json"

# Map an artifact signal -> (human channel, how to extract it on-device).
SIGNAL_DOC = {
    "evidence_record": (
        "DvmaEvidence artifact",
        "adb logcat -s DVMA-EVIDENCE  //  adb pull the app's " "files/dvma-artifacts/<id>.txt",
    ),
    "prefs_write": (
        "SharedPreferences entry",
        "run-as/adb pull shared_prefs/*.xml",
    ),
    "file_write": (
        "file on disk",
        "adb pull from the app's files/documents dir",
    ),
    "sqlite": (
        "SQLite row",
        "adb pull the app database and query it (or drozer)",
    ),
    "network_http": (
        "outbound HTTP/socket request",
        "observe in a proxy / network capture",
    ),
    "clipboard": (
        "system clipboard contents",
        "adb shell service call clipboard / read from another app",
    ),
    "external_dir": (
        "file in external/app documents dir",
        "adb pull the written file",
    ),
    "process_exec": (
        "spawned process",
        "observe via ps / logcat",
    ),
    "passkey_store": (
        "SharedPreferences passkey artifact (+ DVMA-EVIDENCE)",
        "adb pull shared_prefs/*.xml (keys prefixed dvma_passkey_)  //  "
        "adb logcat -s DVMA-EVIDENCE",
    ),
    "provider_bridge": (
        "exported ContentProvider effect (native EvidenceStore + DVMA-EVIDENCE)",
        "adb shell content query/call the exported provider (or drozer)  //  "
        "adb logcat -s DVMA-EVIDENCE",
    ),
    "platform_bridge": (
        "real Android platform effect (Notification/PendingIntent/overlay/"
        "widget/DexClassLoader) recorded to native EvidenceStore",
        "adb shell dumpsys notification  //  adb logcat -s DVMA-EVIDENCE",
    ),
    "resilience_bridge": (
        "native resilience probe result (root/Frida/emulator/debug/tamper)",
        "adb logcat -s DVMA-EVIDENCE (probe result)",
    ),
    "sysprovider_bridge": (
        "system service state (DevicePolicy/IME/MediaProjection/VPN/companion)",
        "adb logcat -s DVMA-EVIDENCE",
    ),
    "webview_host": (
        "real System WebView load/JS-bridge effect",
        "observe WebView behavior on device  //  adb logcat -s DVMA-EVIDENCE",
    ),
}


def main() -> int:
    manifest = json.loads(MANIFEST.read_text())
    inspect = {m["id"]: m for m in json.loads(INSPECT.read_text())["modules"]}

    for mod in manifest["modules"]:
        info = inspect.get(mod["id"])
        if not info:
            continue
        sigs = info.get("artifact_signals", [])
        channels = []
        extract = []
        for s in sigs:
            doc = SIGNAL_DOC.get(s)
            if not doc:
                continue
            channels.append(doc[0])
            if doc[1] not in extract:
                extract.append(doc[1])
        mod["evidence"] = {
            "fidelity": info.get("verdict", "UNCLEAR"),
            "native_backed": info.get("native_backed", False),
            "artifacts": channels or ["in-app evidence panel"],
            "record_kinds": info.get("evidence_records", []),
            "extract": extract or ["observe the in-app EvidencePanel"],
        }

    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    n = sum(1 for m in manifest["modules"] if "evidence" in m)
    print(f"enriched {n}/{len(manifest['modules'])} modules with evidence blocks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
