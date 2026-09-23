#!/usr/bin/env python3
"""Generate the DVMA iOS parity/evidence-tier audit (docs/ios_parity_audit.md).

For every iOS-enabled module (from automation/vuln_manifest.json) this records
how real its finding is on iOS today, one of four tiers:

  A        Pure-Dart real I/O, identical to Android (UserDefaults plist, SQLite,
           temp file, socket, ciphertext). Real on iOS; collected via simctl.
  B-real   Native-bridge module whose iOS Swift probe is implemented, so the
           native signal is real (dvma/resilience, dvma/app_group).
  B-nosim  Native-bridge module modelling an Android-only trust boundary
           (implicit broadcast, exported component, ContentProvider, Binder)
           with no iOS equivalent; runs an in-Dart model on iOS. A native probe
           is intentionally not built.
  C        iOS-only surface still simulated in Dart (App Intents / Shortcuts /
           Universal Links / WKWebView).

Data-driven so it stays in sync with the registry: it reads the manifest plus a
bridge->module map derived from `rg` of lib/modules. Re-run after adding modules
or promoting a bridge to real on iOS.
"""

from __future__ import annotations

import json
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "automation" / "vuln_manifest.json"
OUT = ROOT / "docs" / "ios_parity_audit.md"

# Native bridges and their current iOS reality. Keep in sync with
# lib/core/native/*_bridge.dart (`isAvailable`) and ios/Runner/DvmaNativeProbes.swift.
BRIDGES = {
    "resilience_bridge": {
        "channel": "dvma/resilience",
        "ios": "real",  # DvmaNativeProbes.swift implements all 5 probes for real
        "note": "Real Swift probes: jailbreak markers + sandbox write, sysctl "
        "P_TRACED, simulator env, dyld Frida-image scan + port 27042, "
        "embedded-profile digest.",
    },
    "system_provider_bridge": {
        "channel": "dvma/system_provider",
        "ios": "nosim",
        "note": "Android capability-broker surfaces (a11y/notification-listener/"
        "VPN/IME/device-admin/MediaProjection enablement). Mostly no "
        "direct iOS equivalent; in-Dart model on iOS.",
    },
    "platform_ipc_bridge": {
        "channel": "dvma/platform_ipc",
        "ios": "nosim",
        "note": "Android Intent/PendingIntent/overlay/notification-listener "
        "surfaces, no iOS equivalent.",
    },
    "provider_ipc_bridge": {
        "channel": "dvma/provider_ipc",
        "ios": "nosim",
        "note": "Android ContentProvider / URI-grant / FileProvider, no iOS equivalent.",
    },
    "component_ipc_bridge": {
        "channel": "dvma/component_ipc",
        "ios": "nosim",
        "note": "Android exported components / Intent redirection / Binder, no iOS equivalent.",
    },
    "broadcast_ipc_bridge": {
        "channel": "dvma/broadcast_ipc",
        "ios": "nosim",
        "note": "Android implicit/ordered/dynamic BroadcastReceiver, no iOS equivalent.",
    },
    "otp_broadcast_bridge": {
        "channel": "dvma/otp_broadcast",
        "ios": "nosim",
        "note": "Android implicit-broadcast OTP leak, no iOS broadcast bus.",
    },
    # iOS-native surfaces with a REAL Swift probe implemented in
    # ios/Runner/DvmaNativeProbes.swift (+ DvmaLockscreenIntents.swift). Their
    # `handle()` case is a genuine iOS primitive, not FlutterMethodNotImplemented,
    # so the module's iOS finding is real, not an in-Dart simulation.
    "app_intent_bridge": {
        "channel": "dvma/app_intent",
        "ios": "real",
        "note": "Real iOS App Intents shipped in the Runner binary "
        "(UnlockFrontDoorIntent / ExportAccountIntent) with NO "
        "authenticationPolicy; invocable via Shortcuts and readable in "
        "the app's App Intents metadata.",
    },
    "webview_file_bridge": {
        "channel": "dvma/webview_file",
        "ios": "real",
        "note": "Real WKWebView + WKURLSchemeHandler with file access enabled: "
        "an untrusted URL performs a same-origin read of a seeded "
        "on-disk secret exfiltrated over a WKScriptMessageHandler.",
    },
    "att_bridge": {
        "channel": "dvma/att",
        "ios": "real",
        "note": "Real App Tracking Transparency state via ATTrackingManager "
        "plus the IDFA read (no ATT prompt shown).",
    },
    "notification_bridge": {
        "channel": "dvma/notification",
        "ios": "real",
        "note": "Real iOS local UNNotificationRequest scheduled + read back "
        "from UNUserNotificationCenter, rendered unredacted on the lock "
        "screen.",
    },
    "keychain_bridge": {
        "channel": "dvma/keychain",
        "ios": "real",
        "note": "Real Security.framework Keychain items (SecItemAdd / "
        "CopyMatching / Update) + a CryptoKit HMAC state-integrity check.",
    },
    "native_memory_bridge": {
        "channel": "dvma/native_memory",
        "ios": "real",
        "note": "Real compiled-C strcpy stack overflow in the Runner Mach-O "
        "(parity with Android's libdvma_native.so).",
    },
}


def bridge_for_module() -> dict[str, str]:
    """module_id -> bridge filename, via ripgrep over lib/modules."""
    mapping: dict[str, str] = {}
    for bridge in BRIDGES:
        try:
            out = subprocess.run(
                ["rg", "-l", bridge, "lib/modules"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            ).stdout
        except FileNotFoundError:
            out = ""
        for line in out.splitlines():
            # lib/modules/<cat>/<id>/<id>_screen.dart -> id is parts[3]
            parts = line.split("/")
            if len(parts) >= 5:
                mapping[parts[3]] = bridge
    return mapping


# Keychain modules that DON'T call the native Keychain bridge still persist a
# real recoverable artifact on iOS (SharedPreferences -> NSUserDefaults plist),
# so they are Tier A; only the platform keychain semantics
# (SecItem/kSecAttrAccessible/access-groups) are narrative. The bridge-backed
# keychain modules are promoted to B-real by the bridge lookup below (checked
# first). Matched by module-id substring.
IOS_REAL_PLIST = {
    "keychain": "Writes a real recoverable NSUserDefaults plist on iOS (Tier A); "
    "the SecItem/access-group semantics are narrative for this "
    "module (the bridge-backed keychain modules use a real "
    "Security.framework probe and are B-real).",
}

# iOS surfaces with a real native probe wired via a dedicated channel (not the
# catch-all Android bridge). Keyed by module-id substring.
IOS_APP_GROUP = {
    "app_group": "Real native iOS probe via `dvma/app_group` "
    "(containerURL(forSecurityApplicationGroupIdentifier:) "
    "cross-member write/read). Genuine artifact on an "
    "App-Group-entitled build; honest `entitlement-missing` report "
    "otherwise, then Dart falls back to the in-app simulation.",
}


def classify(mod: dict, bridge_map: dict[str, str]) -> tuple[str, str]:
    """Return (tier_label, reality_note) for an iOS-enabled module."""
    mid = mod["id"]
    # App Group has a real dedicated iOS probe (`dvma/app_group`) even though
    # the module also references the Android system_provider bridge, check it
    # before the generic bridge lookup so it isn't downgraded to B-nosim.
    for key, why in IOS_APP_GROUP.items():
        if key in mid:
            return ("B-real", why)
    # A real native bridge wins next: a module that actually calls a bridge
    # with an implemented iOS Swift probe is B-real regardless of substring
    # heuristics (so bridge-backed keychain modules aren't misfiled as A).
    bridge = bridge_map.get(mid)
    if bridge:
        b = BRIDGES[bridge]
        if b["ios"] == "real":
            return ("B-real", f"Real native iOS probe via `{b['channel']}`. {b['note']}")
        return ("B-nosim", f"In-Dart model on iOS (`{b['channel']}`). {b['note']}")
    for key, why in IOS_REAL_PLIST.items():
        if key in mid:
            return ("A", why)
    # No native bridge -> Tier A (pure-Dart real I/O) unless it's an iOS-only
    # surface that is currently a simulation.
    if mod["platforms"] == ["ios"]:
        return ("C", "iOS-only; in-Dart simulation today (no discrete OS probe wired).")
    return ("A", "Pure-Dart real I/O, identical to Android; collect via simctl.")


def main() -> None:
    raw = json.loads(MANIFEST.read_text())
    mods = raw["modules"]
    ios = [m for m in mods if "ios" in m["platforms"]]
    bridge_map = bridge_for_module()

    rows = []
    tier_counts: Counter[str] = Counter()
    for m in sorted(ios, key=lambda x: (x["category"], x["id"])):
        tier, note = classify(m, bridge_map)
        tier_counts[tier] += 1
        rows.append((m["category"], m["id"], m["title"], tier, note))

    total = len(mods)
    ios_only = len([m for m in mods if m["platforms"] == ["ios"]])
    android_only = len([m for m in mods if m["platforms"] == ["android"]])
    shared = len([m for m in mods if set(m["platforms"]) >= {"android", "ios"}])

    lines: list[str] = []
    lines.append("# iOS parity & evidence-tier audit")
    lines.append("")
    lines.append(
        "_Generated by `automation/scripts/ios_parity_audit.py`. "
        "Re-run after registry/bridge changes._"
    )
    lines.append("")
    lines.append("For every iOS-enabled module, this records how real its finding is on iOS today.")
    lines.append("")
    lines.append("## Totals")
    lines.append("")
    lines.append(
        f"- **{total}** modules total, **{shared}** shared, "
        f"**{ios_only}** iOS-only, **{android_only}** Android-only."
    )
    lines.append(f"- **{len(ios)}** iOS-enabled modules, by evidence tier:")
    lines.append("")
    lines.append("| Tier | Meaning | iOS modules |")
    lines.append("|------|---------|-------------|")
    lines.append(f"| **A** | pure-Dart real I/O (real on iOS, via simctl) | {tier_counts['A']} |")
    lines.append(
        f"| **B-real** | native-bridge with a real Swift iOS probe | {tier_counts['B-real']} |"
    )
    lines.append(
        f"| **B-nosim** | native-bridge, Android-only boundary (no iOS equiv; in-Dart model) | {tier_counts['B-nosim']} |"
    )
    lines.append(f"| **C** | iOS-only surface, in-Dart simulation today | {tier_counts['C']} |")
    lines.append("")
    lines.append(
        "> **B-real** = native-bridge modules whose iOS Swift probe is "
        "actually implemented in `ios/Runner/DvmaNativeProbes.swift` "
        "(+ `DvmaLockscreenIntents.swift` / `DvmaKeychainProbe.swift`): "
        "the 5 `resilience` probes, App Group shared-container "
        "(`dvma/app_group`, entitlement-gated), real App Intents "
        "(`dvma/app_intent`), WKWebView local-file read "
        "(`dvma/webview_file`), local notifications (`dvma/notification`), "
        "ATT/IDFA (`dvma/att`), Keychain (`dvma/keychain`), and the "
        "compiled-C stack overflow (`dvma/native_memory`). App "
        "Group/Keychain degrade honestly (`entitlement-missing` + "
        "in-Dart fallback) on an unsigned build. **B-nosim** should "
        "stay simulated, faking an iOS probe for an Android-only "
        "trust boundary would be dishonest parity."
    )
    lines.append("")
    lines.append("## Per-module")
    lines.append("")
    lines.append("| Category | Module | Tier | iOS evidence reality |")
    lines.append("|----------|--------|------|----------------------|")
    for cat, mid, title, tier, note in rows:
        lines.append(f"| {cat} | `{mid}` | {tier} | {note} |")
    lines.append("")

    OUT.write_text("\n".join(lines))
    print(
        f"Wrote {OUT.relative_to(ROOT)}: {len(ios)} iOS modules "
        f"(A={tier_counts['A']}, B-real={tier_counts['B-real']}, "
        f"B-nosim={tier_counts['B-nosim']}, C={tier_counts['C']})."
    )


if __name__ == "__main__":
    main()
