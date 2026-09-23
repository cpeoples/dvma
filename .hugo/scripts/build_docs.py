#!/usr/bin/env python3
"""Build Hugo documentation for DVMA.

Single source of truth: config/registry/ (meta.yaml + categories/<id>.yaml,
assembled by load_registry()). This mirrors the
ansible-security-scanner docs pipeline, adapted to DVMA's registry:

  1. README.md                       -> content/_index.md   (home page:
                                        intro + What's inside + Documentation +
                                        Project structure; License dropped)
     docs/getting-started/*.md       -> content/getting-started/ (nested section:
                                        _index.md + prerequisites, installing-flutter,
                                        android, ios, build-and-flavors, automation
                                        child pages, wrapped in Hugo front matter)
    docs/device-access.md           -> content/device-access/_index.md (nested
    docs/device-access/<platform>/*    section: intro + safety + per-platform
                                       nav; android/ and ios/ are each their own
                                       nested sub-section with ordered children)
     docs/architecture.md            -> content/architecture/_index.md (nested
     docs/architecture/*.md             section: overview + Mermaid diagram, plus
                                        native-bridges, companion-attacker, and
                                        real-artifact-guarantee child pages)
  2. registry YAML                   -> content/dashboard.md (aggregate table)
                                     -> content/vulnerabilities/<category>.md
                                        (one page per MASVS category, listing
                                        every vuln with its standards mapping)
  3. docs/vulnerabilities/<id>.md    -> content/vulnerabilities/detail/<id>.md
  4. registry `manual_test:` fields -> content/manual-testing/{android,ios}.md

The registry is the ONLY place vulnerability metadata is authored, so the app,
the per-vuln docs stubs, and this site never drift.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
HUGO_DIR = SCRIPT_DIR.parent
ROOT_DIR = HUGO_DIR.parent
REGISTRY_DIR = ROOT_DIR / "config" / "registry"
README = ROOT_DIR / "README.md"
DOCS_DIR = ROOT_DIR / "docs" / "vulnerabilities"
ARCHITECTURE = ROOT_DIR / "docs" / "architecture.md"
ARCHITECTURE_SRC = ROOT_DIR / "docs" / "architecture"
GETTING_STARTED_SRC = ROOT_DIR / "docs" / "getting-started"
DEVICE_ACCESS_SRC = ROOT_DIR / "docs" / "device-access.md"
DEVICE_ACCESS_SRC_DIR = ROOT_DIR / "docs" / "device-access"
CONTENT = HUGO_DIR / "content"

BUILD_TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# The raw-HTML links and asset paths this script injects (breadcrumbs, prev/next
# nav, the hero logo) are not markdown, so Hugo does not prepend baseURL to them.
# On a project Pages site the content lives under a path prefix (e.g. /dvma), so
# a bare "/vulnerabilities/..." would 404. docs.yml passes that prefix here; it
# defaults to empty so a root-baseURL build (local, and the link-check copy)
# still resolves.
SITE_BASEPATH = os.environ.get("DVMA_SITE_BASEPATH", "").rstrip("/")


def siteurl(path: str) -> str:
    """Prefix a root-absolute site path with the deploy baseURL path."""
    return f"{SITE_BASEPATH}{path}"


DIFFICULTY_WEIGHT = {"easy": 0, "medium": 1, "hard": 2}


def _load_mas_links() -> dict[str, str]:
    """id -> canonical relative path on mas.owasp.org for MASWE weaknesses and
    MASTG v2 tests/demos. The platform (ios/android) and MASVS group live in the
    path, not in the id, so we can't derive the URL from the id alone; this map
    is generated from the OWASP MAS search index. Missing/empty is non-fatal:
    the URL builders fall back to the filtered index landing page."""
    p = SCRIPT_DIR / "mas_links.json"
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f).get("paths", {})
    except FileNotFoundError:
        return {}


_MAS_LINKS: dict[str, str] = _load_mas_links()

# Populated from the registry's `meta.tool_links` in main(); maps a tool name to
# its official homepage so tool chips render as links. Tools absent here (e.g.
# descriptive artifacts like "crafted prompt") render as plain code.
TOOL_LINKS: dict[str, str] = {}


# --- Official reference link builders -------------------------------------
# Each mapping id is turned into a clickable "framework chip" that deep-links
# to the authoritative page (NIST/MITRE CWE, the OWASP MASVS/MASTG site, and
# the OWASP Mobile Top 10). This mirrors the ansible-security-scanner docs.


def _cwe_url(cwe: str) -> str:
    num = re.sub(r"[^0-9]", "", cwe)
    return f"https://cwe.mitre.org/data/definitions/{num}.html"


def _masvs_url(mid: str) -> str:
    # e.g. MASVS-CODE-4 -> the specific MASVS-CODE-4 control page (each control
    # has its own page). Fall back to the group page, then the MASVS index.
    m = re.match(r"(MASVS-[A-Z]+-\d+)", mid, re.IGNORECASE)
    if m:
        return f"https://mas.owasp.org/MASVS/controls/{m.group(1).upper()}/"
    g = re.match(r"MASVS-([A-Z]+)", mid, re.IGNORECASE)
    group = g.group(1).upper() if g else ""
    return (
        f"https://mas.owasp.org/MASVS/controls/MASVS-{group}/"
        if group
        else "https://mas.owasp.org/MASVS/"
    )


def _maswe_url(mid: str) -> str:
    # MASWE weakness ids -> canonical per-weakness page under its MASVS group
    # (e.g. MASWE/MASVS-PLATFORM/MASWE-0030/). Falls back to the filtered index.
    path = _MAS_LINKS.get(mid)
    if path:
        return f"https://mas.owasp.org/{path}/"
    return f"https://mas.owasp.org/MASWE/?q={mid}"


def _mastg_v2_url(mid: str) -> str:
    # MASTG v2 TEST ids -> canonical per-test page, which encodes platform and
    # MASVS group (e.g. MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0276/). The
    # platform/group live in the catalog, not the id, so we look them up.
    path = _MAS_LINKS.get(mid)
    if path:
        return f"https://mas.owasp.org/{path}/"
    return f"https://mas.owasp.org/MASTG/tests/?q={mid}"


def _mastg_demo_url(mid: str) -> str:
    # MASTG DEMO ids -> canonical per-demo page (path includes platform + group
    # and repeats the id segment, matching the MAS site structure).
    path = _MAS_LINKS.get(mid)
    if path:
        return f"https://mas.owasp.org/{path}/"
    return f"https://mas.owasp.org/MASTG/demos/?q={mid}"


_OWASP_MOBILE_2024 = {
    "M1": "https://owasp.org/www-project-mobile-top-10/2023-risks/m1-improper-credential-usage",
    "M2": "https://owasp.org/www-project-mobile-top-10/2023-risks/m2-inadequate-supply-chain-security",
    "M3": "https://owasp.org/www-project-mobile-top-10/2023-risks/m3-insecure-authentication-authorization",
    "M4": "https://owasp.org/www-project-mobile-top-10/2023-risks/m4-insufficient-input-output-validation",
    "M5": "https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication",
    "M6": "https://owasp.org/www-project-mobile-top-10/2023-risks/m6-inadequate-privacy-controls",
    "M7": "https://owasp.org/www-project-mobile-top-10/2023-risks/m7-insufficient-binary-protection",
    "M8": "https://owasp.org/www-project-mobile-top-10/2023-risks/m8-security-misconfiguration",
    "M9": "https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage",
    "M10": "https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography",
}


def _chip(label: str, url: str, kind: str) -> str:
    return (
        f'<a class="framework-chip framework-chip-{kind}" '
        f'href="{url}" target="_blank" rel="noopener">{label}</a>'
    )


def _id_platform(mid: str) -> str | None:
    """ios / android / None for a MASTG test or demo id, read from the catalog
    path (e.g. MASTG/tests/ios/... -> ios). None when the id isn't in the map
    or the path has no platform segment (e.g. generic techniques)."""
    path = _MAS_LINKS.get(mid, "")
    if "/ios/" in path:
        return "ios"
    if "/android/" in path:
        return "android"
    return None


def _chips(items: list[str], kind: str, url_fn) -> str:
    if not items:
        return '<span class="framework-chip-empty">-</span>'
    return (
        '<span class="framework-chips">'
        + "".join(_chip(x, url_fn(x), kind) for x in items)
        + "</span>"
    )


def _mastg_chips_grouped(items: list[str], url_fn, platforms: list[str] | None = None) -> str:
    """Render MASTG tests/demos grouped by platform, because a weakness usually
    has a *separate* iOS test and Android test living at different URLs. Each id
    keeps its own canonical link; ids we can't place (no platform in the catalog
    path, e.g. generic techniques) fall into a "Generic" group. Platforms with
    no id show an explicit marker so the gap is honest rather than looking like a
    cross-platform module fully covered on one OS. When the module targets a
    platform (per [platforms]) but OWASP has published no test for it, the marker
    reads "None published" to make clear the gap is the MAS catalog's, not
    DVMA's coverage; a platform the module doesn't target reads a plain "None"."""
    if not items:
        return '<span class="framework-chip-empty">-</span>'

    module_platforms = set(platforms or ["android", "ios"])
    groups: dict[str, list[str]] = {"ios": [], "android": [], "generic": []}
    for x in items:
        groups[_id_platform(x) or "generic"].append(x)

    labels = {"ios": "iOS", "android": "Android", "generic": "Generic"}
    rows: list[str] = []
    # Always show iOS + Android lines (so a one-sided module reads as one-sided);
    # only show Generic when it actually has entries.
    for key in ("ios", "android", "generic"):
        ids = groups[key]
        if key == "generic" and not ids:
            continue
        if ids:
            body = "".join(_chip(x, url_fn(x), "mastg") for x in ids)
        else:
            # "None published" when the module runs on this OS but OWASP has no
            # test for it (the catalog gap); plain "None" otherwise.
            marker = "None published" if key in module_platforms else "None"
            body = f'<span class="framework-chip-none">{marker}</span>'
        rows.append(
            f'<span class="framework-plat-row framework-plat-{key}">'
            f'<span class="platform-chip platform-chip-{key} framework-plat-label">'
            f"{labels[key]}</span>"
            f'<span class="framework-chips">{body}</span>'
            "</span>"
        )
    return '<span class="framework-plat-groups">' + "".join(rows) + "</span>"


def _owasp_chip(mobile_id: str) -> str:
    if not mobile_id:
        return '<span class="framework-chip-empty">-</span>'
    url = _OWASP_MOBILE_2024.get(mobile_id, "https://owasp.org/www-project-mobile-top-10/")
    return _chip(mobile_id, url, "owasp")


_PLATFORM_LABEL = {"android": "Android", "ios": "iOS"}


def _platform_chips(platforms: list[str]) -> str:
    """Render Android / iOS chips for a module (both lit = cross-platform)."""
    ps = platforms or ["android", "ios"]
    order = [p for p in ("android", "ios") if p in ps]
    return (
        '<span class="framework-chips">'
        + "".join(
            f'<span class="platform-chip platform-chip-{p}">' f"{_PLATFORM_LABEL.get(p, p)}</span>"
            for p in order
        )
        + "</span>"
    )


def _tool_chip(tool: str) -> str:
    """Render a single tool as a linked code chip when we have a homepage for
    it, else as plain inline code (descriptive artifacts have no homepage)."""
    url = TOOL_LINKS.get(tool)
    return f"[`{tool}`]({url})" if url else f"`{tool}`"


def _code_list(tools: list[str]) -> str:
    return ", ".join(_tool_chip(t) for t in tools)


def _tools_summary(v: dict) -> str:
    """One-line tools string for the metadata header / exploit set-up step.

    Shows the common tools plus any per-platform additions ("Android: ... ;
    iOS: ...") so cross-platform modules with differing tooling read correctly.
    """
    common = v.get("tools", [])
    android_extra = v.get("tools_android", [])
    ios_extra = v.get("tools_ios", [])
    if not (android_extra or ios_extra):
        return _code_list(common)
    parts = []
    if common:
        parts.append(_code_list(common))
    if android_extra:
        parts.append(f"Android: {_code_list(android_extra)}")
    if ios_extra:
        parts.append(f"iOS: {_code_list(ios_extra)}")
    return " · ".join(parts)


def _tools_bullets(v: dict) -> str:
    """Bulleted 'Expected tooling' list, split by platform when tools differ."""
    common = v.get("tools", [])
    android_extra = v.get("tools_android", [])
    ios_extra = v.get("tools_ios", [])
    if not (android_extra or ios_extra):
        return "".join(f"- {_tool_chip(t)}\n" for t in common)
    out = ""
    if common:
        out += "".join(f"- {_tool_chip(t)}\n" for t in common)
    if android_extra:
        out += "\n**Android**\n\n" + "".join(f"- {_tool_chip(t)}\n" for t in android_extra)
    if ios_extra:
        out += "\n**iOS**\n\n" + "".join(f"- {_tool_chip(t)}\n" for t in ios_extra)
    return out


def _attack_inputs_bullets(v: dict) -> str:
    return "".join(f"- `{a}`\n" for a in v.get("attack_inputs", []))


def _how_it_works(v: dict) -> str:
    """Render the module-specific 'How it works' section from the registry
    `detail` field (the in-app explanation, authored once in the registry so the
    app screen and the docs never drift). Empty when a module has no detail."""
    detail = " ".join((v.get("detail") or "").split())
    if not detail:
        return ""
    return f"## How it works\n\n{detail}\n\n"


def _real_demo_note(v: dict) -> str:
    """Callout for modules with a cross-app/native demo (a separate
    attacker app or native OS path), driven by the registry's `real_demo` block.
    Unlike the generic harness note, this documents the cross-boundary
    attack and the exact command that reproduces it."""
    rd = v.get("real_demo")
    if not rd:
        return ""
    # Separate this callout from the preceding harness-note blockquote so the two
    # don't render as one stacked wall in the theme.
    out = "<br/>\n\n> **Real cross-app demo (not a simulation).** " + rd.get("summary", "").strip()
    if not out.endswith("\n"):
        out += "\n"
    cmd = rd.get("command")
    if cmd:
        out += ">\n> One-command demo (from the repo root):\n>\n> ```sh\n"
        out += "".join(f"> {line}\n" for line in cmd.splitlines())
        out += "> ```\n"
    obs = rd.get("observe")
    if obs:
        out += f">\n> {obs.strip()}\n"
    return out + "\n"


# --- Exploit-step generation ----------------------------------------------
# DVMA is a WHITE-BOX training target: the vulnerable behavior lives in a known
# demo screen and (usually) a helper class. So the "exploit steps" are a
# reproducible lab playbook - open the module, drive the vulnerable path,
# observe the evidence panel, then confirm the contrast/secure path - tailored
# per MASVS category and enriched with the module's suggested tooling. This is
# derived from registry metadata so it stays in sync with the catalog.

# LLM/MCP testers that operate against the model/endpoint behind the app rather
# than the app binary; when a module lists any of these we append a note so the
# docs don't imply you can run them against an APK directly.
_LLM_TOOLS = {"garak", "promptfoo", "MCP scanner"}

# Every DVMA module is a self-contained white-box demo: the screen ships the
# malicious input and simulates the attacker (companion app / crafted intent /
# scanned payload) in-process, so nothing external is required to SEE the bug.
# The Tools/Attack-inputs sections are for reproducing the on-device path on a
# device. This note is emitted on every generated detail page to set that frame.
_HARNESS_NOTE = (
    "> **How to exercise it.** DVMA is the harness - open this module from the "
    "home index and tap the demo action. The screen ships the malicious input "
    "and simulates the attacker (e.g. the companion app, crafted intent, or "
    "scanned payload) in-process, and the evidence panel prints the proof. The "
    "**Tools (optional)** and **Attack inputs** below are only needed to "
    "reproduce the exploit end-to-end on a real device.\n\n"
)

# Per-category "what to attack and how" guidance (recon + exploit + verify).
_CATEGORY_PLAYBOOK = {
    "storage": (
        "Exercise the flow that persists data, then inspect on-device storage "
        "(`adb shell run-as <pkg>` / pull the app sandbox, or `objection`'s "
        "`android keystore`/`ios nsuserdefaults` helpers) and confirm the "
        "sensitive value is present in cleartext or without hardware backing."
    ),
    # iOS-specific override for the storage category (no adb/run-as/Keystore):
    # used when a storage module is iOS-only.
    "storage__ios": (
        "Exercise the flow that persists data, then inspect the app sandbox "
        "(`objection`'s `ios nsuserdefaults`/`ios plist cat`/`ios keychain "
        "dump` helpers, or pull the container over `ifuse`) and confirm the "
        "sensitive value is present in cleartext or without hardware backing."
    ),
    "crypto": (
        "Capture the algorithm/key/IV the module uses (the evidence panel "
        "prints it), then reproduce the weakness offline - e.g. recompute the "
        "digest, brute the short key, or decrypt a captured blob - to show the "
        "protection is ineffective."
    ),
    "auth": (
        "Drive the authentication/authorization path, capture the token / "
        "assertion / decision, then replay or tamper with it (mitmproxy, a "
        "WebAuthn test harness, or by editing the value) and confirm the "
        "server-side check accepts the manipulated request."
    ),
    "network": (
        "Route the app through an intercepting proxy (Burp/mitmproxy) with your "
        "CA installed, trigger the network call, and confirm you can read or "
        "modify traffic (cleartext, weak TLS, or a trivially-bypassed pin)."
    ),
    "platform": (
        "From a co-resident/attacker context (`adb shell am start`/`drozer`, or "
        "a crafted deep link / QR), send the untrusted input to the exported "
        "component or WebView and confirm the app performs the unsafe action "
        "(navigation, JS execution, file/URI access) with no validation."
    ),
    # iOS-specific override for the platform category (no Intents/exported
    # components / adb): used when a platform module is iOS-only.
    "platform__ios": (
        "From an attacker context (a crafted custom-URL-scheme / Universal Link, "
        "a malicious document provider / share extension, or a Shortcut), send "
        "the untrusted input to the handler and confirm the app performs the "
        "unsafe action (navigation, file/URL access, privileged operation) with "
        "no validation."
    ),
    "code_quality": (
        "Statically inspect the shipped artifact (`jadx`, `strings`, `nm`, "
        "`aapt dump badging`) and confirm the build/quality weakness is present "
        "in the release binary."
    ),
    "resilience": (
        "Attach an instrumentation tool (`frida`/`objection`) and hook or patch "
        "the single client-side check, confirming the protection flips to "
        "'pass' and the guarded functionality unlocks."
    ),
    "supply_chain": (
        "Inspect the dependency/SDK surface (lockfiles, bundled SDKs, update "
        "channel) and confirm the untrusted or unverified component is accepted "
        "- e.g. a substituted package, an unsigned artifact, or a silent "
        "post-deploy update."
    ),
    "privacy": (
        "Trigger the data-access/telemetry path and confirm sensitive data is "
        "collected, transmitted, or associated without the required consent / "
        "transparency prompt."
    ),
    "input_validation": (
        "Feed the crafted/malformed input (serialized blob, intent extra, "
        "media file, deep link) into the parsing path and confirm the app "
        "trusts it - state change, crash/DoS, or code path it should reject."
    ),
    "ai_ml": (
        "Send the crafted prompt / poisoned content to the in-app assistant and "
        "confirm the model obeys it - leaked system prompt/secret, an "
        "unconfirmed tool call, or attacker-controlled output."
    ),
    "agentic": (
        "Interact with the agent's memory / tool / sub-agent channel, plant the "
        "malicious content, and confirm it influences a later action or is "
        "acted on without authentication."
    ),
    "ai_mobile": (
        "Deliver attacker content across the mobile boundary (deep link / "
        "clipboard / QR) into the assistant, or steer the model's OUTPUT into a "
        "WebView / intent / tool call, and confirm it executes with no "
        "validation boundary in between."
    ),
    "native_bridge": (
        "Reach the JS<->native bridge (or the framework/plugin API) from "
        "untrusted web content / a cross-origin iframe / a malicious provider, "
        "and confirm the privileged native call fires with no main-frame/origin, "
        "callback-id, or permission gate in between."
    ),
    "system_provider": (
        "Drive the provider-activation / enablement workflow (accessibility, "
        "notification-listener, VPN, IME, phone-account, MediaProjection, "
        "credential-provider) and confirm the granted capability is invoked on an "
        "untrusted caller's behalf - the enablement flow is the boundary."
    ),
}


def _exploit_steps(v: dict, cat_id: str, cat_title: str) -> str:
    """Build a reproducible lab playbook for one module from its metadata."""
    title = v.get("title", v.get("id", ""))
    mastg_v2 = v.get("mastg_v2", [])
    platforms = v.get("platforms") or ["android", "ios"]
    ios_only = platforms == ["ios"]
    android_only = platforms == ["android"]
    if ios_only:
        device = "an iOS simulator / a device you control"
    elif android_only:
        device = "an Android emulator you control"
    else:
        device = "an emulator/simulator you control"
    tools_summary = _tools_summary(v)
    tools_str = tools_summary if tools_summary else "the suggested tooling"
    # Prefer a platform-specific playbook variant when one exists (e.g. the
    # iOS override for the Android-flavored `platform` category).
    playbook = _CATEGORY_PLAYBOOK.get(
        f"{cat_id}__ios" if ios_only else cat_id,
        _CATEGORY_PLAYBOOK.get(
            cat_id,
            "Drive the vulnerable path in the demo screen and confirm the insecure "
            "behavior from the on-screen evidence panel.",
        ),
    )
    has_detail = bool((v.get("detail") or "").strip())
    locate = (
        f"**Locate the target.** From the home index, open **{title}** "
        f"(`{v.get('id','')}`). "
        + (
            "The **How it works** section above describes this module's specific "
            "weakness; the screen states the intended-secure behavior and exposes "
            "the vulnerable action."
            if has_detail
            else "The screen states the intended-secure behavior and exposes the "
            "vulnerable action."
        )
    )
    steps = [
        f"**Set up.** Build DVMA with a flavor that enables the *{cat_title}* "
        f"category (e.g. `--dart-define-from-file=config/flavors/dev.json`) and "
        f"run on {device}. The demo needs no external tooling; for the optional "
        f"on-device reproduction the relevant tools are: {tools_str}.",
        locate,
        f"**Exploit.** {playbook}",
        "**Observe the evidence.** Trigger the vulnerable action and read the "
        "evidence panel - it prints the concrete proof (leaked value, accepted "
        "replay, executed payload, or unauthorized result).",
        "**Contrast with the secure path.** Run the module's secure/hardened "
        "action (where provided) and confirm the same attack is rejected - this "
        "is what a correct implementation should do.",
    ]
    if mastg_v2:
        steps.append(
            "**Map it back.** Cross-reference the MASTG v2 test(s) "
            + ", ".join(f"[{m}]({_mastg_v2_url(m)})" for m in mastg_v2)
            + " for the canonical procedure and remediation."
        )
    return "## Exploit steps\n\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1)) + "\n"


def load_registry() -> dict:
    """Assemble the logical registry from the split source files.

    The registry is authored as config/registry/meta.yaml (metadata + the
    canonical category order) plus, for each category, either a single
    config/registry/categories/<id>.yaml OR a directory
    config/registry/categories/<id>/ of numbered *.yaml shards (used when a
    category has grown large, e.g. platform). Shards are merged in sorted
    filename order with their `vulnerabilities` concatenated. We merge
    everything here into the single {"meta", "categories"} mapping the rest of
    the pipeline expects, preserving category order.
    """
    with open(REGISTRY_DIR / "meta.yaml") as f:
        meta_doc = yaml.safe_load(f) or {}
    order = meta_doc.get("category_order", [])
    categories = {}
    for cat_id in order:
        cat_dir = REGISTRY_DIR / "categories" / cat_id
        cat_file = REGISTRY_DIR / "categories" / f"{cat_id}.yaml"
        if cat_dir.is_dir():
            merged = None
            vulns = []
            for shard in sorted(cat_dir.glob("*.yaml")):
                with open(shard) as f:
                    shard_cat = (yaml.safe_load(f) or {})[cat_id]
                if merged is None:
                    merged = dict(shard_cat)
                vulns.extend(shard_cat.get("vulnerabilities", []))
            merged["vulnerabilities"] = vulns
            categories[cat_id] = merged
        else:
            with open(cat_file) as f:
                categories[cat_id] = (yaml.safe_load(f) or {})[cat_id]
    return {"meta": meta_doc.get("meta", {}), "categories": categories}


def clean_content() -> None:
    if CONTENT.exists():
        for child in CONTENT.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            elif child.name != "_index.md":
                child.unlink()
    CONTENT.mkdir(parents=True, exist_ok=True)


def _badge(difficulty: str) -> str:
    d = difficulty.lower()
    return f'<span class="dvma-badge dvma-{d}">{d.upper()}</span>'


_LEADING_H1_RE = re.compile(r"^#\s+.+?\n+", re.MULTILINE)
_STUB_TRAINING_RE = re.compile(r"^>\s*\*\*Training only\.\*\*.*?$\n+", re.MULTILINE)
_STUB_METADATA_TABLE_RE = re.compile(r"\|\s*Field\s*\|\s*Value\s*\|.*?(?=\n##|\n#|\Z)", re.S)
_STUB_STANDARDS_RE = re.compile(r"\n##\s+Standards mapping.*?(?=\n##\s|\Z)", re.S)


def _strip_leading_h1(text: str) -> str:
    return _LEADING_H1_RE.sub("", text, count=1)


def _strip_stub_boilerplate(text: str) -> str:
    """Remove the redundant bits of the scaffolded doc stub.

    The chip-based metadata header (rendered separately) supersedes the stub's
    "Training only" banner, the raw metadata table, and the plaintext
    "Standards mapping" list. Drop those so the detail page reads cleanly."""
    # Drop the "> **Training only.** ..." blockquote.
    text = _STUB_TRAINING_RE.sub("", text)
    # Drop the leading "| Field | Value |" metadata table.
    text = _STUB_METADATA_TABLE_RE.sub("", text, count=1)
    # Drop the trailing "## Standards mapping" section (chips cover it).
    text = _STUB_STANDARDS_RE.sub("\n", text)
    return text.strip() + "\n"


def _references_block(references: list) -> str:
    """Render a 'Real-world references' section from `label|url` strings."""
    if not references:
        return ""
    out = "\n## Real-world references\n\n"
    out += "Concrete public disclosures that match this vulnerability class:\n\n"
    for ref in references:
        if "|" in ref:
            label, url = ref.split("|", 1)
            out += f"- [{label.strip()}]({url.strip()})\n"
        else:
            out += f"- {ref}\n"
    return out


def _rewrite_readme_assets(content: str) -> str:
    """Point the README's repo-relative links/assets at the Hugo-served copies.

    The README is authored for GitHub, so it links to repo-relative paths
    (`automation/README.md`, `docs/architecture.md`). When the same source is
    rendered as the site home page those paths 404, so map the ones we surface
    to their published site URLs. Fragments are dropped because the target site
    pages do not carry the README's in-file anchors."""
    content = re.sub(
        r'<img\s+src="docs/assets/dvma-logo\.svg"[^>]*>',
        f'<img src="{siteurl("/assets/dvma-logo.svg")}" '
        'alt="DVMA - Damn Vulnerable Mobile App" '
        'class="dvma-hero">',
        content,
        count=1,
    )
    content = content.replace('src="docs/assets/', f'src="{siteurl("/assets/")}')

    link_map = {
        "automation/README.md": "/getting-started/automation/",
        "docs/architecture.md": "/architecture/",
    }
    for src, dest in link_map.items():
        content = re.sub(
            rf"\]\(\s*{re.escape(src)}(?:#[^)]*)?\s*\)",
            f"]({dest})",
            content,
        )

    # The home page carries the README preamble but not its `## Contributing`
    # section (see _HOME_SECTIONS), so the preamble's `[Contributing](#contributing)`
    # anchor has no target here. Point it at the dedicated site page instead.
    content = re.sub(
        r"\]\(\s*#contributing\s*\)",
        "](/getting-started/contributing/)",
        content,
    )

    # Drop the shields.io badge block: it's GitHub-repo chrome (CI/license/etc.)
    # that is redundant and broken-looking on the docs home page. Authored between
    # the BADGES_START/END sentinels in README.md.
    content = re.sub(
        r"(?s)<!--\s*BADGES_START.*?<!--\s*BADGES_END\s*-->\s*",
        "",
        content,
    )
    return content


def _readme_sections() -> "tuple[str, dict]":
    """Split README.md into its preamble + a {heading: section-markdown} map.

    Sections are keyed by their `## ` heading text. This lets the docs home and
    the Getting Started page each pull the sections they need from the single
    README source, so nothing drifts.
    """
    raw = _strip_leading_h1(README.read_text() if README.exists() else "# DVMA\n")
    raw = _rewrite_readme_assets(raw)
    parts = re.split(r"(?m)^(##\s+.+)$", raw)
    preamble = parts[0]
    sections = {}
    for i in range(1, len(parts), 2):
        heading = parts[i]
        title = heading[2:].strip()
        sections[title] = heading + parts[i + 1]
    return preamble, sections


# README sections that make up the home page (Getting Started + Device Access
# are now authored under docs/ rather than lifted from the README).
_HOME_SECTIONS = ["Quickstart (5 minutes)", "What's inside", "Documentation", "Project structure"]


def build_index() -> None:
    preamble, sections = _readme_sections()
    # Drop the README's in-page "Contents" list -- the docs sidebar replaces it.
    preamble = re.sub(r"(?ms)^##\s+Contents\b.*?(?=^##\s+|\Z)", "", preamble)
    # Nudge readers from the landing page to the dedicated guide.
    preamble = preamble.rstrip() + (
        "\n\n**New here?** Start with the "
        "**[Getting Started](/getting-started/)** guide — install Flutter, build "
        "the app, and install it on a device.\n\n"
    )
    body = preamble + "".join(sections[h] for h in _HOME_SECTIONS if h in sections)
    front = (
        "---\n"
        'title: "Damn Vulnerable Mobile App"\n'
        'linkTitle: "DVMA"\n'
        'description: "A single-codebase, intentionally vulnerable Flutter app '
        "for mobile security training. Maps to OWASP Mobile Top 10 (2024), "
        'MASVS/MASTG, and the OWASP Top 10 for LLM/GenAI (2025)."\n'
        "weight: 1\n"
        "alwaysopen: true\n"
        f'lastmod: "{BUILD_TS}"\n'
        "---\n\n"
    )
    (CONTENT / "_index.md").write_text(front + body)
    print("  content/_index.md")


def _child_page(
    out_dir: Path,
    path: str,
    title: str,
    weight: int,
    body: str,
    desc: str = "",
) -> None:
    """Write one section child page (front matter + lifted body) into [out_dir].

    Shared by the Getting Started, Device Access, and Architecture sections —
    they all wrap a committed docs/ body in the same title/linkTitle/[desc]/
    weight front matter, so the format lives in exactly one place.
    """
    front = "---\n" f'title: "{title}"\n' f'linkTitle: "{title}"\n'
    if desc:
        front += f'description: "{desc}"\n'
    front += f"weight: {weight}\n" f'lastmod: "{BUILD_TS}"\n' "---\n\n"
    (out_dir / path).write_text(front + body.strip() + "\n")
    print(f"  content/{out_dir.name}/{path}")


def _build_section_children(out_dir: Path, src_dir: Path, pages: list) -> None:
    """Write a section's child pages from committed docs/ bodies.

    [pages] is a list of (src_filename, out_filename, title, weight, desc). Warns
    (and continues) if any source is missing so a rename surfaces loudly.
    """
    missing = [src for src, *_ in pages if not (src_dir / src).exists()]
    if missing:
        print(f"  WARNING: missing {out_dir.name} sources: {missing}")
    for src, out, title, weight, desc in pages:
        _child_page(out_dir, out, title, weight, (src_dir / src).read_text(), desc)


def _build_nested_subsection(
    parent_dir: Path,
    src_dir: Path,
    name: str,
    title: str,
    weight: int,
    desc: str,
    pages: list,
) -> None:
    """Write ONE nested Hugo sub-section (a folder with its own _index + children).

    [src_dir] is the committed source folder (e.g. docs/device-access/android);
    it must hold an `_index.md` body plus each child body named in [pages]. Emits
    content/<parent>/<name>/_index.md (collapsible) + one leaf per page. Used to
    give Android/iOS their own expandable sub-menus under Root & Jailbreak.
    """
    idx_src = src_dir / "_index.md"
    if not idx_src.exists():
        print(f"  WARNING: missing {src_dir}/_index.md; skipping {name}/ subsection")
        return
    sub_dir = parent_dir / name
    sub_dir.mkdir(parents=True, exist_ok=True)

    index_front = (
        "---\n"
        f'title: "{title}"\n'
        f'linkTitle: "{title}"\n'
        f'description: "{desc}"\n'
        f"weight: {weight}\n"
        "collapsibleMenu: true\n"
        "alwaysopen: false\n"
        f'lastmod: "{BUILD_TS}"\n'
        "---\n\n"
    )
    (sub_dir / "_index.md").write_text(index_front + idx_src.read_text().strip() + "\n")
    print(f"  content/{parent_dir.name}/{name}/_index.md")

    _build_section_children(sub_dir, src_dir, pages)


def build_getting_started() -> None:
    """Emit the nested "Getting Started" Hugo section from committed sources.

    The section's six child pages are authored as committed body files under
    docs/getting-started/ (prerequisites, installing-flutter, android, ios,
    build-and-flavors, automation). This builder reads each body verbatim and
    wraps it in the section's front matter — the SOURCE lives in docs/ so the
    README can be a light landing page, but the rendered output is unchanged.
    """
    # (relative source filename, output filename, title, weight, description)
    pages = [
        (
            "prerequisites.md",
            "prerequisites.md",
            "Prerequisites",
            1,
            "Set up your host toolchain and any physical Android/iOS test "
            "devices before building DVMA.",
        ),
        (
            "installing-flutter.md",
            "installing-flutter.md",
            "Installing Flutter",
            2,
            "Install the latest stable Flutter on macOS, Linux, or Windows.",
        ),
        (
            "android.md",
            "android.md",
            "Android",
            3,
            "Run DVMA on an Android emulator end-to-end, and clone → build → "
            "`adb install` it onto a physical phone.",
        ),
        (
            "ios.md",
            "ios.md",
            "iOS",
            4,
            "Install DVMA on a physical iPhone with Xcode, or terminal-only via "
            "ideviceinstaller / ios-deploy / applesign.",
        ),
        (
            "build-and-flavors.md",
            "build-and-flavors.md",
            "Build & Flavors",
            5,
            "Build commands, finding your device id, build flavors, and "
            "platform-specific (Android vs iOS) modules.",
        ),
        (
            "automation.md",
            "automation.md",
            "Automation",
            6,
            "Drive every module with Appium/UI automation, run the test suite, "
            "and add a new vulnerability to the registry.",
        ),
        (
            "ci-and-releases.md",
            "ci-and-releases.md",
            "CI & Releases",
            7,
            "How CI builds both platforms unsigned on every change, and how "
            "tagged releases produce signed, installable APK/IPA artifacts.",
        ),
        (
            "contributing.md",
            "contributing.md",
            "Contributing",
            8,
            "Standards mapping (MASVS/CWE/MASWE/OWASP) and the validation gates "
            "every module contribution must pass.",
        ),
    ]

    gs_dir = CONTENT / "getting-started"
    gs_dir.mkdir(parents=True, exist_ok=True)

    # --- Section landing page (_index.md) ---------------------------------
    index_front = (
        "---\n"
        'title: "Getting Started"\n'
        'linkTitle: "Getting Started"\n'
        'description: "Install Flutter, build DVMA, and install it on an Android '
        'or iOS device."\n'
        "weight: 2\n"
        "collapsibleMenu: true\n"
        "alwaysopen: false\n"
        f'lastmod: "{BUILD_TS}"\n'
        "---\n\n"
    )
    index_body = (
        "Everything you need to go from a fresh clone to DVMA running on a "
        "device or emulator. Work through these in order:\n\n"
        "1. **[Prerequisites](prerequisites/)** — host toolchain + physical "
        "device setup.\n"
        "2. **[Installing Flutter](installing-flutter/)** — macOS / Linux / "
        "Windows.\n"
        "3. **[Android](android/)** — run on an emulator and install on a "
        "physical phone via `adb`.\n"
        "4. **[iOS](ios/)** — install on a physical iPhone (Xcode or "
        "terminal-only).\n"
        "5. **[Build & Flavors](build-and-flavors/)** — build commands, finding "
        "your device, flavors, and per-platform modules.\n"
        "6. **[Automation](automation/)** — Appium/UI automation, testing, and "
        "adding a new vulnerability.\n"
        "7. **[CI & Releases](ci-and-releases/)** — how CI builds both platforms "
        "unsigned, and how tagged releases produce signed artifacts.\n"
        "8. **[Contributing](contributing/)** — standards mapping and the "
        "validation gates for new modules.\n"
    )
    (gs_dir / "_index.md").write_text(index_front + index_body)
    print("  content/getting-started/_index.md")

    _build_section_children(gs_dir, GETTING_STARTED_SRC, pages)


def build_device_access() -> None:
    """Emit the nested "Device Access" Hugo section from committed sources.

    The landing page (docs/device-access.md) carries the intro + safety warning
    + per-platform nav; Android and iOS are each their own NESTED sub-section
    (docs/device-access/<platform>/ with an _index.md + ordered child bodies) so
    the left menu expands per platform instead of two long scroll-pages.
    All bodies are already heading-demoted (subsections at `## `), so we just
    prepend front matter — the SOURCE lives in docs/ but the output is unchanged.
    """
    if not DEVICE_ACCESS_SRC.exists():
        print(f"  WARNING: missing {DEVICE_ACCESS_SRC}; " "skipping content/device-access/")
        return
    da_dir = CONTENT / "device-access"
    da_dir.mkdir(parents=True, exist_ok=True)

    index_front = (
        "---\n"
        'title: "Root, Jailbreak & Recover Artifacts"\n'
        'linkTitle: "Root & Jailbreak"\n'
        'description: "Root a Pixel (Magisk) or jailbreak an iOS device '
        '(Dopamine), then recover the real on-device artifacts DVMA writes."\n'
        "weight: 15\n"
        "collapsibleMenu: true\n"
        "alwaysopen: false\n"
        f'lastmod: "{BUILD_TS}"\n'
        "---\n\n"
    )
    (da_dir / "_index.md").write_text(index_front + DEVICE_ACCESS_SRC.read_text())
    print("  content/device-access/_index.md")

    # Android and iOS are each their own NESTED sub-section (a folder with an
    # _index landing + ordered child pages), so the left menu expands per
    # platform instead of showing two very long scroll-pages. Sources live under
    # docs/device-access/<platform>/ (one _index.md + one body per child).
    _build_nested_subsection(
        da_dir,
        DEVICE_ACCESS_SRC_DIR / "android",
        "android",
        "Android",
        1,
        "Root a Pixel 8a/6a with Magisk (GUI, terminal, or the autonomous "
        "root_pixel.sh script), recover a brick, and pull artifacts.",
        [
            (
                "root-magisk.md",
                "root-magisk.md",
                "Root with Magisk",
                1,
                "Unlock, patch the stock boot image (GUI or terminal-only), "
                "flash it, and verify root.",
            ),
            (
                "script.md",
                "script.md",
                "Autonomous script",
                2,
                "root_pixel.sh: auto-fetch Magisk + the matching factory image, "
                "patch, and optionally flash — fully unattended.",
            ),
            (
                "recover.md",
                "recover.md",
                "Recover a bricked device",
                3,
                "dm-verity/AVB notes, bootloop triage, and a full factory "
                "re-flash (flash-all or the Android Flash Tool).",
            ),
            (
                "verify.md",
                "verify.md",
                "Verify artifacts",
                4,
                "Pull the artifact with adb on a debuggable build, or via "
                "su/frida on a rooted device.",
            ),
        ],
    )
    _build_nested_subsection(
        da_dir,
        DEVICE_ACCESS_SRC_DIR / "ios",
        "ios",
        "iOS",
        2,
        "Jailbreak a supported iPhone/iPad — Dopamine 3 (A12+, iOS ≤16.x) or "
        "palera1n/checkm8 (A8–A11, any iOS incl. 17/18) — then recover artifacts "
        "via a backup, SSH/SCP/Filza, or the Simulator.",
        [
            (
                "download.md",
                "download.md",
                "Download Dopamine",
                1,
                "Where to get Dopamine and which file (.ipa vs .tipa) to grab.",
            ),
            (
                "install.md",
                "install.md",
                "Install Dopamine",
                2,
                "Pick ONE installer (Sideloadly / AltStore / SideStore / "
                "TrollStore / CLI) and follow its self-contained recipe.",
            ),
            (
                "run.md",
                "run.md",
                "Run the jailbreak",
                3,
                "Trust the profile (per-installer), run Dopamine, pick a package "
                "manager, and install OpenSSH.",
            ),
            (
                "palera1n.md",
                "palera1n.md",
                "palera1n (A8–A11)",
                4,
                "checkm8 jailbreak for A8–A11 devices (iPhone 6s/7/8/X, iPad "
                "5/6/7) on ANY iOS incl. 17/18 — the path Dopamine can't cover.",
            ),
            (
                "verify.md",
                "verify.md",
                "Verify artifacts",
                5,
                "Recover the artifact via an unencrypted backup, SSH/SCP/Filza "
                "on a jailbroken device, or the Simulator.",
            ),
        ],
    )


def build_dashboard(reg: dict) -> None:
    categories = reg["categories"]
    total = sum(len(c.get("vulnerabilities", [])) for c in categories.values())

    page = f'---\ntitle: "Dashboard"\nweight: 5\n' f'lastmod: "{BUILD_TS}"\n---\n\n'
    page += "## Coverage overview\n\n"
    page += "| Metric | Value |\n|--------|-------|\n"
    page += f"| Total vulnerabilities | **{total}** |\n"
    page += f"| MASVS categories | **{len(categories)}** |\n"
    page += "| Standards | OWASP Mobile Top 10 (2024), MASVS/MASTG, OWASP LLM Top 10 (2025), OWASP Agentic Top 10 (2025) |\n\n"

    page += "## Vulnerabilities by category\n\n"
    page += '<div class="dvma-table">\n\n'
    page += "| Category | OWASP Mobile | Count | Easy | Medium | Hard |\n"
    page += "|----------|--------------|-------|------|--------|------|\n"
    for cat_id, cat in categories.items():
        vulns = cat.get("vulnerabilities", [])
        by_diff = {"easy": 0, "medium": 0, "hard": 0}
        for v in vulns:
            by_diff[v.get("difficulty", "medium")] += 1
        label = cat.get("title", cat_id)
        page += (
            f"| [{label}](/vulnerabilities/{cat_id}/) "
            f"| {cat.get('owasp_mobile', '')} | {len(vulns)} "
            f"| {by_diff['easy']} | {by_diff['medium']} | {by_diff['hard']} |\n"
        )
    page += "\n</div>\n"
    (CONTENT / "dashboard.md").write_text(page)
    print("  content/dashboard.md")


def build_category_pages(reg: dict) -> None:
    categories = reg["categories"]
    vdir = CONTENT / "vulnerabilities"
    vdir.mkdir(parents=True, exist_ok=True)

    index_front = (
        "---\n"
        'title: "Vulnerabilities"\nweight: 10\n'
        "collapsibleMenu: true\nalwaysopen: false\n"
        f'lastmod: "{BUILD_TS}"\n---\n\n'
    )
    index_body = (
        "Every DVMA vulnerability, organized by OWASP MASVS category. Each "
        "entry maps to the OWASP Mobile Top 10 (2024), MASVS/MASTG, CWE, and "
        "(for the AI/ML module) the OWASP Top 10 for LLM/GenAI (2025).\n\n"
        "See the [Dashboard](/dashboard/) for the coverage matrix.\n"
    )
    (vdir / "_index.md").write_text(index_front + index_body)

    for weight_idx, (cat_id, cat) in enumerate(categories.items(), start=1):
        vulns = sorted(
            cat.get("vulnerabilities", []),
            key=lambda v: (
                DIFFICULTY_WEIGHT.get(v.get("difficulty", "medium"), 1),
                v.get("id", ""),
            ),
        )
        label = cat.get("title", cat_id)
        page = (
            f'---\ntitle: "{label}"\nweight: {weight_idx * 10}\n' f'lastmod: "{BUILD_TS}"\n---\n\n'
        )
        desc = " ".join((cat.get("description") or "").split())
        if desc:
            page += f"{desc}\n\n"
        page += f"**{len(vulns)}** vulnerabilities. OWASP Mobile: {_owasp_chip(cat.get('owasp_mobile', ''))}\n\n"
        page += '<div class="pattern-table">\n\n'
        page += "| Vulnerability | ID | Platform | Difficulty | OWASP | MASVS | MASWE | MASTG (v2) | CWE |\n"
        page += "|---------------|----|:--------:|:----------:|:-----:|:-----:|:-----:|:----------:|:---:|\n"
        for v in vulns:
            vid = v.get("id", "")
            page += (
                f"| [{v.get('title', vid)}](/vulnerabilities/detail/{vid}/) "
                f'| <code class="vuln-id">{vid}</code> '
                f"| {_platform_chips(v.get('platforms', []))} "
                f"| {_badge(v.get('difficulty', 'medium'))} "
                f"| {_owasp_chip(v.get('owasp_mobile', cat.get('owasp_mobile', '')))} "
                f"| {_chips(v.get('masvs', []), 'masvs', _masvs_url)} "
                f"| {_chips(v.get('maswe', []), 'maswe', _maswe_url)} "
                f"| {_chips(v.get('mastg_v2', []), 'mastg', _mastg_v2_url)} "
                f"| {_chips(v.get('cwe', []), 'cwe', _cwe_url)} |\n"
            )
        page += "\n</div>\n"
        (vdir / f"{cat_id}.md").write_text(page)
        print(f"  content/vulnerabilities/{cat_id}.md ({len(vulns)})")


def build_detail_pages(reg: dict) -> None:
    detail = CONTENT / "vulnerabilities" / "detail"
    detail.mkdir(parents=True, exist_ok=True)
    (detail / "_index.md").write_text(
        f'---\ntitle: "Detail"\nweight: 999\n'
        f'hidden: true\nlastmod: "{BUILD_TS}"\n---\n\n'
        "Per-vulnerability detail pages.\n"
    )
    count = 0
    for cat_id, cat in reg["categories"].items():
        cat_owasp = cat.get("owasp_mobile", "")
        cat_title = cat.get("title", "")
        # Page findings in the SAME order the category page renders them
        # (difficulty then id) so top back-link + prev/next line up with the list.
        ordered = sorted(
            cat.get("vulnerabilities", []),
            key=lambda v: (
                DIFFICULTY_WEIGHT.get(v.get("difficulty", "medium"), 1),
                v.get("id", ""),
            ),
        )
        for pos, v in enumerate(ordered):
            vid = v["id"]
            prev_v = ordered[pos - 1] if pos > 0 else None
            next_v = ordered[pos + 1] if pos < len(ordered) - 1 else None
            front = f'---\ntitle: "{v.get("title", vid)}"\n' f'lastmod: "{BUILD_TS}"\n---\n\n'
            # Top crumb: one click back to the exact category the user came from.
            crumb_url = siteurl(f"/vulnerabilities/{cat_id}/")
            crumb = (
                f'<p class="detail-crumb"><a href="{crumb_url}">' f"&larr; {cat_title}</a></p>\n\n"
            )
            # Thorough metadata header: difficulty + clickable framework chips
            # (OWASP Mobile, MASVS, MASTG, CWE) + tools.
            owasp_id = v.get("owasp_mobile", cat_owasp)
            header = (
                f'<code class="vuln-id">{vid}</code> &nbsp; '
                f'{_badge(v.get("difficulty", "medium"))}\n\n'
                "| | |\n|---|---|\n"
                f"| **Category** | {cat_title} |\n"
            )
            if v.get("severity"):
                header += f"| **Severity** | {v['severity']} |\n"
            header += (
                f"| **OWASP Mobile (2024)** | {_owasp_chip(owasp_id)} |\n"
                f"| **MASVS** | {_chips(v.get('masvs', []), 'masvs', _masvs_url)} |\n"
            )
            # MAS 2.0 mappings (MASWE weakness + MASTG v2 tests / demos): only
            # rendered when the module has a genuine mapping (never fabricated).
            if v.get("maswe"):
                header += f"| **MASWE** | " f"{_chips(v.get('maswe', []), 'maswe', _maswe_url)} |\n"
            if v.get("mastg_v2"):
                header += (
                    f"| **MASTG (v2 tests)** | "
                    f"{_mastg_chips_grouped(v.get('mastg_v2', []), _mastg_v2_url, v.get('platforms'))} |\n"
                )
            if v.get("mastg_demo"):
                header += (
                    f"| **MASTG demos** | "
                    f"{_mastg_chips_grouped(v.get('mastg_demo', []), _mastg_demo_url, v.get('platforms'))} |\n"
                )
            header += (
                f"| **CWE** | {_chips(v.get('cwe', []), 'cwe', _cwe_url)} |\n"
                f"| **Platform** | {_platform_chips(v.get('platforms', []))} |\n"
            )
            note = (v.get("platform_note") or "").strip()
            if note:
                header += f"| **Platform notes** | {note} |\n"
            tools = v.get("tools", [])
            has_tools = bool(tools or v.get("tools_android") or v.get("tools_ios"))
            attack_inputs = v.get("attack_inputs", [])
            # Tools and attack inputs are rendered in richer, platform-split
            # sections in the body below, so they're intentionally omitted from
            # this summary table to avoid duplicating them on the page.
            header += "\n---\n\n"

            # Body is built from the registry so it never drifts and carries no
            # placeholder TODOs: Description -> generated Exploit steps ->
            # Expected tooling. A hand-authored detail doc is preferred only when
            # it is NOT an unedited scaffold (scaffolds carry a
            # `dvma:generated-stub` marker); a filled-in page drops that marker.
            summary = v.get("summary", "")
            src = DOCS_DIR / f"{vid}.md"
            authored = ""
            if src.exists():
                raw = src.read_text()
                if "dvma:generated-stub" not in raw:
                    stub = _strip_stub_boilerplate(_strip_leading_h1(raw))
                    if stub.strip():
                        authored = stub

            if authored:
                body = authored + "\n"
            else:
                body = f"## Description\n\n{summary}\n\n" if summary else ""
                body += _how_it_works(v)
                body += _HARNESS_NOTE
                body += _real_demo_note(v)
                body += _exploit_steps(v, cat_id, cat_title)
                if has_tools:
                    body += "\n## Tools (optional)\n\n" + _tools_bullets(v)
                    if _LLM_TOOLS & set(
                        v.get("tools", []) + v.get("tools_android", []) + v.get("tools_ios", [])
                    ):
                        body += (
                            "\n_`garak` / `promptfoo` / `MCP scanner` test the "
                            "**LLM or MCP endpoint behind the app**, not the app "
                            "binary. Point them at the backend model API (find it "
                            "with `mitmproxy` / `Burp Suite`) or a local on-device "
                            "model server; the in-app demo already exercises the "
                            "same prompt path._\n"
                        )
                if attack_inputs:
                    body += (
                        "\n## Attack inputs\n\n"
                        "Payloads/artifacts you author for the on-device attack. "
                        "The demo already ships and simulates these in-process "
                        "(e.g. the malicious companion app / crafted intent is "
                        "emulated inside the screen), so you only need to craft "
                        "them to reproduce the exploit on a real device:\n\n"
                        + _attack_inputs_bullets(v)
                    )
                body += "\n"

            footer = _references_block(v.get("references", []))
            # Footer nav: page laterally through the category, or jump back to
            # its list. Mirrors the category ordering above.
            cat_url = siteurl(f"/vulnerabilities/{cat_id}/")
            if prev_v:
                prev_url = siteurl(f"/vulnerabilities/detail/{prev_v['id']}/")
                prev_title = prev_v.get("title", prev_v["id"])
                prev_link = (
                    f'<a class="detail-nav-prev" href="{prev_url}">' f"&larr; {prev_title}</a>"
                )
            else:
                prev_link = "<span></span>"
            if next_v:
                next_url = siteurl(f"/vulnerabilities/detail/{next_v['id']}/")
                next_title = next_v.get("title", next_v["id"])
                next_link = (
                    f'<a class="detail-nav-next" href="{next_url}">' f"{next_title} &rarr;</a>"
                )
            else:
                next_link = "<span></span>"
            footer += (
                '\n<nav class="detail-nav">\n'
                f"{prev_link}\n"
                f'<a class="detail-nav-up" href="{cat_url}">'
                f"{cat_title}</a>\n"
                f"{next_link}\n"
                "</nav>\n"
            )
            (detail / f"{vid}.md").write_text(front + crumb + header + body + footer)
            count += 1
    print(f"  content/vulnerabilities/detail/*.md ({count})")


def build_architecture() -> None:
    """Emit the nested "Architecture" Hugo section from committed sources.

    The landing page (docs/architecture.md) carries the overview + Mermaid
    diagram; three child pages under docs/architecture/ cover the specifics.
    """
    if not ARCHITECTURE.exists():
        return
    arch_dir = CONTENT / "architecture"
    arch_dir.mkdir(parents=True, exist_ok=True)

    # Landing page: front matter + the (h1-stripped) overview/diagram body.
    index_front = (
        "---\n"
        'title: "Architecture"\n'
        'linkTitle: "Architecture"\n'
        "description: \"How DVMA's Flutter UI, native Android host, and companion "
        "attacker app work together to produce real, device-extractable "
        'artifacts."\n'
        "weight: 3\n"
        "collapsibleMenu: true\n"
        "alwaysopen: false\n"
        f'lastmod: "{BUILD_TS}"\n'
        "---\n\n"
    )
    (arch_dir / "_index.md").write_text(index_front + _strip_leading_h1(ARCHITECTURE.read_text()))
    print("  content/architecture/_index.md")

    # (relative source filename, output filename, title, weight, description)
    pages = [
        (
            "native-bridges.md",
            "native-bridges.md",
            "Native Bridges",
            1,
            "How the Flutter and Kotlin halves talk over MethodChannels, and "
            "how the native op + EvidenceStore read-back works.",
        ),
        (
            "companion-attacker.md",
            "companion-attacker.md",
            "Companion Attacker",
            2,
            "Why a cross-app adversary needs its own app, and the cross-app "
            "modules com.dvma.attacker exploits.",
        ),
        (
            "real-artifact-guarantee.md",
            "real-artifact-guarantee.md",
            "The Real-Artifact Guarantee",
            3,
            "How every module produces a device-extractable artifact, "
            "end-to-end verification, and the iOS evidence tiers.",
        ),
    ]
    _build_section_children(arch_dir, ARCHITECTURE_SRC, pages)


def build_manual_testing() -> None:
    """Generate the Manual Testing section from the registry.

    Single source of truth: each module's optional `manual_test:` field in the
    registry. This emits a nested section with an Android and an iOS child page,
    each listing only the modules that (a) declare a `manual_test` step and (b)
    apply to that platform (from the module's `platforms` field; absent = both).
    Modules fully proven by the in-app `integration_test/` suite omit
    `manual_test` and correctly don't appear here.
    """
    reg = load_registry()
    order = list(reg["categories"].keys())

    # (category_title, [(id, manual_test)]) per platform, preserving registry order.
    def rows_for(platform: str) -> list[tuple[str, list[tuple[str, str]]]]:
        out = []
        for cat_id in order:
            cat = reg["categories"][cat_id]
            items = []
            for v in cat.get("vulnerabilities", []):
                step = (v.get("manual_test") or "").strip()
                if not step:
                    continue
                plats = v.get("platforms") or ["android", "ios"]
                if platform in plats:
                    items.append((v["id"], step))
            if items:
                out.append((cat.get("title", cat_id), items))
        return out

    md = CONTENT / "manual-testing"
    md.mkdir(parents=True, exist_ok=True)

    index_front = (
        "---\n"
        'title: "Manual Testing"\n'
        'linkTitle: "Manual Testing"\n'
        'description: "External-tool verification steps (MITM, Frida, drozer, '
        "static analysis) the in-app test suite can't drive, split per "
        'platform."\n'
        "weight: 20\n"
        "collapsibleMenu: true\n"
        "alwaysopen: false\n"
        f'lastmod: "{BUILD_TS}"\n'
        "---\n\n"
    )
    index_body = (
        "> **Authorized training/testing use only.** DVMA is intentionally "
        "vulnerable. Do not run these steps against apps or infrastructure you "
        "are not authorized to test.\n\n"
        "These checklists cover what the in-app automated `integration_test/` "
        "suite **structurally cannot** validate: checks that need an external "
        "tool (an active MITM proxy, a Frida hook, static analysis of the "
        "compiled APK/IPA, an attacking companion app). Modules fully proven "
        "in-app omit a manual step and don't appear here.\n\n"
        "The steps are **generated from the registry** (`manual_test:` on each "
        "module) and split by the module's `platforms`, so they never drift "
        "from the catalog. Pick your platform:\n\n"
        "- **[Android](android/)** — root/`adb`/drozer/`apksigner`-driven checks.\n"
        "- **[iOS](ios/)** — jailbreak/objection/Keychain/App-Intents checks.\n\n"
        "Common tooling: [Frida](https://frida.re), "
        "[objection](https://github.com/sensepost/objection), "
        "[mitmproxy](https://mitmproxy.org) / Burp Suite, "
        "[drozer](https://github.com/WithSecureLabs/drozer), "
        "[jadx](https://github.com/skylot/jadx), `adb`, `apksigner`.\n"
    )
    (md / "_index.md").write_text(index_front + index_body)
    print("  content/manual-testing/_index.md")

    for platform, title, weight, blurb in (
        ("android", "Android", 1, "Manual verification steps for every Android-applicable module."),
        ("ios", "iOS", 2, "Manual verification steps for every iOS-applicable module."),
    ):
        sections = rows_for(platform)
        count = sum(len(items) for _, items in sections)
        parts = [
            "---\n"
            f'title: "{title}"\n'
            f'linkTitle: "{title}"\n'
            f'description: "{blurb}"\n'
            f"weight: {weight}\n"
            f'lastmod: "{BUILD_TS}"\n'
            "---\n\n"
            f"**{count}** {title} manual-verification steps, grouped by "
            "category. Each is a module that needs an external tool the in-app "
            "suite can't drive.\n"
        ]
        for cat_title, items in sections:
            parts.append(f"\n## {cat_title}\n\n")
            for vid, step in items:
                parts.append(f"- [ ] **{vid}**, {step}\n")
        (md / f"{platform}.md").write_text("".join(parts))
        print(f"  content/manual-testing/{platform}.md ({count} steps)")


def main() -> None:
    print("Building DVMA Hugo docs from the vulnerability registry...")
    reg = load_registry()
    TOOL_LINKS.update(reg.get("meta", {}).get("tool_links", {}))
    clean_content()
    build_index()
    build_getting_started()
    build_device_access()
    build_architecture()
    build_dashboard(reg)
    build_category_pages(reg)
    build_detail_pages(reg)
    build_manual_testing()
    total = sum(len(c.get("vulnerabilities", [])) for c in reg["categories"].values())
    print(f"Done: {total} vulnerabilities across {len(reg['categories'])} categories.")


if __name__ == "__main__":
    main()
