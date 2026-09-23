// lib/dvma.js
//
// Shared helpers for the DVMA (Damn Vulnerable Mobile App) automation suite.
//
// DVMA is an intentionally-vulnerable *target* app used for security training.
// Every widget an automation script needs to touch is instrumented in
// `lib/core/test_ids.dart` via the `testId(id, child)` helper, which attaches
// BOTH:
//   * a Flutter `ValueKey<String>(id)`   -> found by appium-flutter-driver
//                                            with `find.byValueKey('<id>')`
//   * a `Semantics(identifier: id)` node -> surfaces as an Android `resource-id`
//                                            (UiAutomator2) and an iOS
//                                            `accessibilityIdentifier` (XCUITest),
//                                            locatable natively by accessibility id.
//
// These helpers branch on the *live session's* automationName so the same test
// specs run unchanged against the Flutter driver OR native UiAutomator2/XCUITest.
//
// The set of ids/modules is NOT hardcoded here: we load the generated manifest
// at `automation/vuln_manifest.json` (produced by `tool/generate.dart`). Adding
// a module and re-running the generator automatically extends coverage.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** Absolute path to the generated manifest (../.. -> automation/). */
export const MANIFEST_PATH = path.resolve(__dirname, '..', '..', 'vuln_manifest.json');

/**
 * Stable home-screen control ids mirrored from lib/core/test_ids.dart. These
 * are not in the generated manifest's `ids` block (which only carries the three
 * boot markers), but they are load-bearing for the walk and are relied on by
 * the XCUITest and Espresso suites too, so we pin them here.
 */
export const HOME_IDS = {
  expandAll: 'dvma_expand_all',
  clearSearch: 'dvma_clear_search',
  moduleManifest: 'dvma_module_manifest',
};

/**
 * Default application/bundle id, mirrored from the Android `applicationId`
 * (android/app/build.gradle.kts) and DVMA_APP_ID. The iOS wdio config derives
 * its `bundleId` capability from this too (via BUNDLE_ID), so app-relaunch in
 * `recoverToHome` and the launched app never drift apart. Override with the
 * BUNDLE_ID env var.
 */
export const DEFAULT_BUNDLE_ID = process.env.BUNDLE_ID || 'com.dvma';

/**
 * Load and parse the generated automation manifest.
 * @returns {{
 *   ids: { searchField: string, flavorBadge: string, disclaimerBanner: string },
 *   categories: Array<{ id: string, title: string }>,
 *   count: number,
 *   modules: Array<{ id: string, category: string, title: string,
 *                    difficulty: string, rowId: string, screenId: string }>
 * }}
 */
export function loadManifest() {
  const raw = fs.readFileSync(MANIFEST_PATH, 'utf8');
  const manifest = JSON.parse(raw);
  if (!Array.isArray(manifest.modules) || manifest.modules.length === 0) {
    throw new Error(`Manifest at ${MANIFEST_PATH} has no modules`);
  }
  return manifest;
}

/**
 * True when the current session is driven by appium-flutter-driver, in which
 * case we locate widgets by their Flutter ValueKey rather than by native
 * accessibility id.
 * @param {WebdriverIO.Browser} driver
 * @returns {boolean}
 */
export function isFlutterSession(driver) {
  const caps = driver.capabilities || {};
  const requested =
    (driver.requestedCapabilities && driver.requestedCapabilities['appium:automationName']) || '';
  const active = caps.automationName || caps['appium:automationName'] || requested || '';
  return String(active).toLowerCase() === 'flutter';
}

/**
 * Build a WebdriverIO selector for the given DVMA id, appropriate for the
 * active driver:
 *   * Flutter driver  -> the Flutter finder JSON `{ using: 'key', value: id }`
 *                        which the driver interprets as `find.byValueKey(id)`.
 *   * Native drivers  -> the accessibility-id selector `~<id>`, which resolves
 *                        against the Semantics identifier (Android resource-id /
 *                        iOS accessibilityIdentifier).
 * @param {WebdriverIO.Browser} driver
 * @param {string} id
 * @returns {string}
 */
export function selectorFor(driver, id) {
  if (isFlutterSession(driver)) {
    // appium-flutter-driver accepts a serialized Flutter finder as the selector.
    return JSON.stringify({ using: 'key', value: id });
  }
  // Flutter's Semantics(identifier:) surfaces differently per native platform:
  //   * Android (UiAutomator2) -> resource-id (NOT content-desc, so `~id` misses)
  //   * iOS (XCUITest)         -> accessibilityIdentifier, matched by `~id`
  if (driver.isAndroid) {
    return `android=new UiSelector().resourceId("${id}")`;
  }
  return `~${id}`;
}

/**
 * Resolve a single element for a DVMA id (does not wait).
 * @param {WebdriverIO.Browser} driver
 * @param {string} id
 * @returns {Promise<WebdriverIO.Element>}
 */
export async function findById(driver, id) {
  return driver.$(selectorFor(driver, id));
}

/**
 * Whether an element with the given DVMA id is currently present & displayed.
 * Never throws; returns false on any lookup error.
 * @param {WebdriverIO.Browser} driver
 * @param {string} id
 * @param {number} [timeoutMs=4000]
 * @returns {Promise<boolean>}
 */
export async function isPresent(driver, id, timeoutMs = 4000) {
  try {
    const el = await findById(driver, id);
    await el.waitForDisplayed({ timeout: timeoutMs });
    return true;
  } catch {
    return false;
  }
}

/**
 * Wait until an element with the given id is displayed, then return it.
 * Throws if it never appears.
 * @param {WebdriverIO.Browser} driver
 * @param {string} id
 * @param {number} [timeoutMs=10000]
 * @returns {Promise<WebdriverIO.Element>}
 */
export async function waitForId(driver, id, timeoutMs = 10000) {
  const el = await findById(driver, id);
  await el.waitForDisplayed({ timeout: timeoutMs });
  return el;
}

/**
 * Scroll the home list until an element with `id` is found, then return it.
 *
 * The DVMA home screen uses a lazy `ListView.builder`, so off-screen rows are
 * not in the tree until scrolled into view. Strategy differs by driver:
 *   * Native drivers: use the platform scrollable locator strategy
 *     (UiScrollable on Android; a repeated swipe fallback on iOS/XCUITest).
 *   * Flutter driver: the driver exposes a `flutter:scrollIntoView` command
 *     that scrolls a keyed widget into view directly.
 *
 * @param {WebdriverIO.Browser} driver
 * @param {string} id
 * @param {number} [maxSwipes=25]
 * @returns {Promise<WebdriverIO.Element>}
 */
export async function scrollToId(driver, id, maxSwipes = 25) {
  // Fast path: already on screen.
  if (await isPresent(driver, id, 1500)) {
    return findById(driver, id);
  }

  if (isFlutterSession(driver)) {
    // appium-flutter-driver: scroll the keyed widget into view.
    try {
      await driver.execute('flutter:scrollIntoView', selectorFor(driver, id), {
        alignment: 0.1,
      });
    } catch {
      // Fall through to swipe-based scrolling below.
    }
    if (await isPresent(driver, id, 2500)) {
      return findById(driver, id);
    }
  } else if (driver.isAndroid) {
    // UiAutomator2: let UiScrollable find a resource-id inside the first
    // scrollable container. This is the most reliable native approach.
    try {
      const uiSelector =
        'new UiScrollable(new UiSelector().scrollable(true).instance(0))' +
        `.scrollIntoView(new UiSelector().resourceId("${id}"))`;
      const el = await driver.$(`android=${uiSelector}`);
      if (await el.isExisting()) return el;
    } catch {
      // Fall through to manual swipe.
    }
  }

  // Generic manual-swipe fallback (works on iOS native and as a backstop).
  for (let i = 0; i < maxSwipes; i++) {
    if (await isPresent(driver, id, 800)) {
      return findById(driver, id);
    }
    await swipeUp(driver);
  }

  // Last attempt so the caller gets a real element handle (or a clean failure).
  const el = await findById(driver, id);
  await el.waitForDisplayed({ timeout: 3000 });
  return el;
}

/**
 * Swipe up (scroll down) roughly one viewport using the W3C actions API.
 * @param {WebdriverIO.Browser} driver
 */
export async function swipeUp(driver) {
  const { width, height } = await driver.getWindowSize();
  const startX = Math.floor(width / 2);
  const startY = Math.floor(height * 0.75);
  const endY = Math.floor(height * 0.3);
  await driver.performActions([
    {
      type: 'pointer',
      id: 'finger1',
      parameters: { pointerType: 'touch' },
      actions: [
        { type: 'pointerMove', duration: 0, x: startX, y: startY },
        { type: 'pointerDown', button: 0 },
        { type: 'pause', duration: 100 },
        { type: 'pointerMove', duration: 350, x: startX, y: endY },
        { type: 'pointerUp', button: 0 },
      ],
    },
  ]);
  await driver.releaseActions();
}

/**
 * Open a module by tapping its home-list row (`vuln_row_<id>`), scrolling it
 * into view first if needed.
 * @param {WebdriverIO.Browser} driver
 * @param {string} rowId  e.g. "vuln_row_insecure_local_storage"
 * @returns {Promise<void>}
 */
export async function openModule(driver, rowId) {
  const row = await scrollToId(driver, rowId);
  await row.click();
}

/**
 * Navigate back to the previous screen.
 *   * Android: hardware/system back.
 *   * iOS: tap the nav bar back button if present, else swipe from the left
 *     edge (interactive pop gesture).
 * @param {WebdriverIO.Browser} driver
 */
export async function back(driver) {
  if (driver.isAndroid) {
    await driver.back();
    return;
  }

  // iOS: tap the AppBar back button that Flutter renders. After a slider drag
  // the accessibility tree can briefly go stale, so retry a few times with a
  // short settle before falling back to the interactive-pop edge swipe.
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      const backBtn = await driver.$('~Back');
      if (await backBtn.isExisting()) {
        await backBtn.click();
        return;
      }
    } catch {
      // tree not ready yet
    }
    await driver.pause(500);
  }

  const { width, height } = await driver.getWindowSize();
  const y = Math.floor(height / 2);
  await driver.performActions([
    {
      type: 'pointer',
      id: 'finger1',
      parameters: { pointerType: 'touch' },
      actions: [
        { type: 'pointerMove', duration: 0, x: 5, y },
        { type: 'pointerDown', button: 0 },
        { type: 'pause', duration: 100 },
        { type: 'pointerMove', duration: 300, x: Math.floor(width * 0.9), y },
        { type: 'pointerUp', button: 0 },
      ],
    },
  ]);
  await driver.releaseActions();
}

/**
 * Return to a clean, searchable home by relaunching the app - the iOS analogue
 * of Android's launch-intent recovery, and the same approach the XCUITest walk
 * uses (recoverToHome). Used when back-navigation leaves the app in an unknown
 * state (e.g. after a slider drag stales the tree). Never throws.
 * @param {WebdriverIO.Browser} driver
 * @param {string} bundleId
 */
export async function recoverToHome(driver, bundleId = DEFAULT_BUNDLE_ID) {
  try {
    if (driver.isIOS) {
      await driver.execute('mobile: terminateApp', { bundleId });
      await driver.execute('mobile: activateApp', { bundleId });
    } else {
      await driver.reset?.();
    }
    await waitForId(driver, 'dvma_search_field', 20000);
  } catch {
    // best-effort; the caller's next search will surface any remaining issue
  }
}

/**
 * Tap the "expand all" app-bar toggle so every category section is open and all
 * `vuln_row_*` rows are built into the tree. Category sections are collapsed by
 * default, so this must run before any row lookup. Best-effort: if the control
 * isn't found (older build) the walk falls back to scrolling.
 * @param {WebdriverIO.Browser} driver
 * @returns {Promise<boolean>} whether the toggle was tapped
 */
export async function expandAllCategories(driver) {
  try {
    const el = await findById(driver, HOME_IDS.expandAll);
    await el.waitForDisplayed({ timeout: 8000 });
    await el.click();
    // Let the sections animate open before rows are queried.
    await driver.pause(600);
    return true;
  } catch {
    return false;
  }
}

/**
 * Read the app's OWN runtime list of enabled module ids from the hidden
 * `dvma_module_manifest` node's accessibility label (a CSV of ids produced by
 * VulnerabilityRegistry.enabledFor). This is the drift-proof source of truth -
 * preferred over the repo-side vuln_manifest.json. Returns [] if unavailable so
 * the caller can fall back to the file manifest.
 * @param {WebdriverIO.Browser} driver
 * @returns {Promise<string[]>}
 */
export async function moduleIdsFromApp(driver) {
  // The manifest node carries its CSV in the accessibility label/value, not as
  // an on-screen widget, so we read the attribute rather than display state.
  const readCsv = async () => {
    const el = await findById(driver, HOME_IDS.moduleManifest);
    if (!(await el.isExisting())) return '';
    // iOS surfaces the Semantics label as `label`/`value`; Android as `text`
    // /content-desc. Try the common attributes and take the first non-empty.
    for (const attr of ['value', 'label', 'name', 'content-desc', 'text']) {
      const v = await el.getAttribute(attr).catch(() => '');
      if (v && v.includes(',')) return v;
      if (v && /^[a-z0-9_]+$/.test(v)) return v;
    }
    return (await el.getText().catch(() => '')) || '';
  };
  try {
    const csv = await readCsv();
    return csv
      .split(',')
      .map((s) => s.trim())
      .filter((s) => /^[a-z0-9_]+$/.test(s));
  } catch {
    return [];
  }
}

/**
 * Empty the search field so the next query starts clean. The app renders its
 * own clear (X) button with id `dvma_clear_search` whenever the field is
 * non-empty; tapping it reliably clears the Flutter TextField (a plain
 * clearValue() is a no-op on this field). Best-effort and never throws.
 * @param {WebdriverIO.Browser} driver
 */
export async function clearSearch(driver) {
  try {
    const x = await findById(driver, HOME_IDS.clearSearch);
    if (await x.isExisting()) {
      await x.click();
      await driver.pause(250);
    }
  } catch {
    // best-effort
  }
}

/**
 * Navigate to a module BY SEARCH (mirrors the XCUITest/Espresso walks): type
 * the id into the search field, tap the single matching row, and confirm the
 * demo screen. Falls back to scroll-nav if the search box is unavailable. One
 * retry (clear + retype) before giving up, since the first keystroke can race
 * the keyboard on iOS.
 * @param {WebdriverIO.Browser} driver
 * @param {{id:string,rowId:string,screenId:string}} mod
 * @returns {Promise<boolean>} whether the demo screen was reached
 */
export async function openModuleBySearch(driver, mod) {
  const search = 'dvma_search_field';
  for (let attempt = 0; attempt < 3; attempt++) {
    // If the search field isn't reachable we're not on home (a module pushed a
    // WebView/route and back didn't fully pop). Relaunch to a clean home rather
    // than thrashing the remaining attempts against a screen with no search box.
    if (!(await isPresent(driver, search, attempt === 0 ? 4000 : 1500))) {
      await recoverToHome(driver);
    }
    try {
      await clearSearch(driver); // always start from an empty field
      const field = await waitForId(driver, search, 10000);
      await field.click();
      await enterText(driver, field, mod.id);
      await driver.pause(500);
      const row = await findById(driver, mod.rowId);
      if (await row.isDisplayed().catch(() => false)) {
        await row.click();
        if (await isPresent(driver, mod.screenId, 10000)) return true;
      }
    } catch {
      // retry (clear, then relaunch on the next pass)
    }
    await clearSearch(driver);
  }
  return false;
}

/**
 * Robust text entry that works across driver flavors. The Flutter driver and
 * UiAutomator2 accept setValue directly; native XCUITest on a Flutter TextField
 * sometimes lacks keyboard focus, so we retry via keys() after a tap.
 * @param {WebdriverIO.Browser} driver
 * @param {WebdriverIO.Element} field
 * @param {string} text
 */
export async function enterText(driver, field, text) {
  if (driver.isAndroid) {
    // The Flutter TextField doesn't expose its contents via UiAutomator2's
    // `text` attribute (getText() is always ""), and setValue doesn't reliably
    // land here. Focusing then sending keystrokes does - the caller verifies
    // success by the filtered row appearing, not by reading the field back.
    try {
      await field.click();
      await driver.keys(text.split(''));
      return;
    } catch {
      // fall through to setValue as a last resort
    }
    await field.setValue(text).catch(() => {});
    return;
  }
  try {
    await field.setValue(text);
    return;
  } catch {
    // fall through to key-based entry
  }
  try {
    await field.click();
    await driver.keys(text.split(''));
  } catch {
    // best-effort; the caller asserts the resulting row
  }
}

/**
 * Flip every switch and nudge every slider on the current demo screen so a
 * module that gates its vulnerable path on a control state is exercised before
 * the action buttons fire. Best-effort; failures never abort the walk.
 *
 * Flutter renders these controls as `XCUIElementTypeOther` (no native Switch/
 * Slider type) and Android as real widget classes, so we target by attribute:
 *   * iOS  - a slider exposes a percentage `value` (e.g. "18%"); a switch a
 *            "0"/"1" value. We match those with an -ios predicate.
 *   * Android - real Switch / SeekBar classes.
 *
 * On iOS, dragging a Flutter slider collapses sibling `demo_action_*` nodes out
 * of the accessibility tree until the screen is rebuilt (verified: no in-place
 * refresh restores them). We therefore report whether a slider was dragged so
 * the walk can re-open the module before tapping its actions.
 * @param {WebdriverIO.Browser} driver
 * @returns {Promise<boolean>} true if a slider was dragged (iOS tree now stale)
 */
export async function exerciseControls(driver) {
  if (isFlutterSession(driver)) return false; // no generic attribute query for Flutter keys
  if (driver.isAndroid) {
    for (const sel of [
      'android=new UiSelector().className("android.widget.Switch")',
      'android=new UiSelector().className("android.widget.SeekBar")',
    ]) {
      try {
        for (const el of await driver.$$(sel)) await el.click().catch(() => {});
      } catch {
        // ignore
      }
    }
    return false;
  }
  // iOS: toggle switches (value 0/1), then push each adjustable slider high.
  // Flutter sliders surface as XCUIElementTypeOther with traits="Adjustable"
  // (not a native Slider), and setValue is a no-op on them - so we drag the
  // thumb across the screen width, which does move the value (18% -> 100%).
  try {
    for (const sw of await driver.$$("-ios predicate string:value == '0' OR value == '1'")) {
      await sw.click().catch(() => {});
    }
  } catch {
    // ignore
  }
  try {
    const sliders = await driver.$$("-ios predicate string:traits CONTAINS 'Adjustable'");
    const { width: screenW } = await driver.getWindowSize();
    let dragged = false;
    for (const sl of sliders) {
      try {
        const loc = await sl.getLocation();
        const size = await sl.getSize();
        const y = Math.floor(loc.y + size.height / 2);
        await driver.performActions([
          {
            type: 'pointer',
            id: 'finger1',
            parameters: { pointerType: 'touch' },
            actions: [
              { type: 'pointerMove', duration: 0, x: Math.floor(loc.x + size.width / 2), y },
              { type: 'pointerDown', button: 0 },
              { type: 'pause', duration: 150 },
              { type: 'pointerMove', duration: 500, x: Math.floor(screenW * 0.92), y },
              { type: 'pointerUp', button: 0 },
            ],
          },
        ]);
        await driver.releaseActions();
        dragged = true;
      } catch {
        // ignore this slider; keep going
      }
    }
    return dragged;
  } catch {
    return false;
  }
}

/**
 * Tap EVERY `demo_action_*` button on the current demo screen (not just the
 * first): modules can gate evidence on a specific/non-first button, or split
 * vuln/secure across buttons, so we fire them all. The Flutter Semantics id
 * surfaces to Appium as the element `name` (there is no `identifier` attribute
 * in the XCUITest source), so native iOS matches on `name`; Android matches the
 * resource-id. The Flutter driver can't prefix-match ValueKeys, so it returns 0.
 * @param {WebdriverIO.Browser} driver
 * @returns {Promise<number>} number of action buttons tapped
 */
export async function tapAllDemoActions(driver) {
  if (isFlutterSession(driver)) return 0;
  const selector = driver.isAndroid
    ? 'android=new UiSelector().resourceIdMatches("demo_action_.*")'
    : "-ios predicate string:name BEGINSWITH 'demo_action_'";
  let tapped = 0;
  try {
    // Snapshot count first; tapping rebuilds the tree (evidence panels appear)
    // and would invalidate live indices.
    const initial = await driver.$$(selector);
    const count = initial.length;
    for (let i = 0; i < count; i++) {
      try {
        const fresh = await driver.$$(selector);
        const btn = fresh[i];
        if (btn && (await btn.isDisplayed().catch(() => false))) {
          await btn.click();
          tapped += 1;
          await driver.pause(250);
        }
      } catch {
        // keep going; one stubborn button shouldn't sink the module
      }
    }
  } catch {
    // no action buttons on this screen
  }
  return tapped;
}

/**
 * Whether at least one `evidence_*` panel is present on the current screen -
 * the on-device proof that a vulnerable path actually ran. Matches on `name`
 * (iOS) / resource-id (Android), mirroring [tapAllDemoActions].
 * @param {WebdriverIO.Browser} driver
 * @returns {Promise<boolean>}
 */
export async function hasEvidence(driver) {
  if (isFlutterSession(driver)) return false; // can't prefix-match ValueKeys
  try {
    const selector = driver.isAndroid
      ? 'android=new UiSelector().resourceIdMatches("evidence_.*")'
      : "-ios predicate string:name BEGINSWITH 'evidence_'";
    return await (await driver.$(selector)).isExisting();
  } catch {
    return false;
  }
}

/**
 * Ensure the artifacts directory exists and return its absolute path.
 * @returns {string}
 */
export function artifactsDir() {
  const dir = path.resolve(__dirname, '..', 'artifacts');
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Save a PNG screenshot of the current screen to artifacts/<name>.png.
 * @param {WebdriverIO.Browser} driver
 * @param {string} name  file stem (module id)
 * @returns {Promise<string>} the absolute path written
 */
export async function screenshot(driver, name) {
  const dir = artifactsDir();
  const safe = String(name).replace(/[^a-z0-9_.-]+/gi, '_');
  const file = path.join(dir, `${safe}.png`);
  await driver.saveScreenshot(file);
  return file;
}
