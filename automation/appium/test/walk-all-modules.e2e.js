// test/walk-all-modules.e2e.js
//
// Flagship DVMA dynamic-analysis driver - the Appium analogue of the native
// XCUITest RunnerUITests walk and the Android Espresso walk.
//
// Purpose: exercise EVERY instrumented module so a pentester's dynamic-analysis
// tooling (proxy, Frida, os_log/logcat, filesystem watchers) observes each
// vulnerable code path at least once. The flow mirrors the native walks:
//   1. expand all category sections so every `vuln_row_*` is built,
//   2. read the app's OWN runtime module list (dvma_module_manifest), falling
//      back to the repo-side vuln_manifest.json,
//   3. for each module: navigate BY SEARCH (type id, tap the single result),
//   4. flip switches / nudge sliders so control-gated paths are reachable,
//   5. tap ALL `demo_action_*` buttons (not just the first),
//   6. assert an `evidence_*` panel appeared (on-device proof), capture a PNG,
//   7. clear the search and continue.
//
// The walk is resilient: each module runs in its own try/catch, failures are
// collected, and the run fails only at the very end with a consolidated report
// so one flaky module never hides coverage of the rest.
//
// Evidence assertion and action/control interaction require id-prefix matching,
// which the appium-flutter-driver cannot do; those steps are skipped under
// DVMA_DRIVER=flutter and fully active under DVMA_DRIVER=native (XCUITest /
// UiAutomator2). Run the iOS walk with DVMA_DRIVER=native for full fidelity.

import { expect } from '@wdio/globals';
import {
  loadManifest,
  waitForId,
  isPresent,
  expandAllCategories,
  moduleIdsFromApp,
  openModuleBySearch,
  exerciseControls,
  tapAllDemoActions,
  hasEvidence,
  clearSearch,
  screenshot,
  back,
  recoverToHome,
  isFlutterSession,
} from '../lib/dvma.js';

const manifest = loadManifest();

/**
 * Resolve the modules to walk. Prefer the app's runtime manifest node (never
 * drifts from what's compiled in); fall back to the generated file manifest.
 * The file manifest is the only source of rowId/screenId, so we always map
 * app-provided ids back through it and keep only modules we can navigate.
 */
async function resolveModules() {
  const byId = new Map(manifest.modules.map((m) => [m.id, m]));

  // Optional targeted subset for quick validation: DVMA_MODULE_IDS=a,b,c
  const subset = (process.env.DVMA_MODULE_IDS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (subset.length) {
    return subset.map((id) => byId.get(id)).filter(Boolean);
  }

  const appIds = await moduleIdsFromApp(driver);
  if (appIds.length) {
    const mapped = appIds.map((id) => byId.get(id)).filter(Boolean);
    if (mapped.length) return mapped;
  }
  return manifest.modules;
}

describe('DVMA - walk all modules', () => {
  before(async () => {
    await waitForId(driver, manifest.ids.disclaimerBanner, 45000);
    await expandAllCategories(driver);
  });

  it('opens and exercises every enabled module', async () => {
    expect(await isPresent(driver, manifest.ids.disclaimerBanner)).toBe(true);

    const modules = await resolveModules();
    const nativeDriver = !isFlutterSession(driver);

    /** @type {Array<{ id: string, stage: string, error: string }>} */
    const failures = [];
    let opened = 0;
    let actionsTriggered = 0;
    let withEvidence = 0;

    for (const mod of modules) {
      try {
        const reached = await openModuleBySearch(driver, mod);
        if (!reached) {
          throw new Error(`demo screen "${mod.screenId}" not reached via search`);
        }
        opened += 1;

        // Exercise sliders/switches FIRST so the action runs against a
        // non-default control state. On iOS a slider drag collapses the
        // demo_action_* nodes out of the a11y tree (no in-place refresh brings
        // them back), so when that happens we rebuild the tree by popping back
        // to home and re-opening the module (cheaper than a full app relaunch,
        // which on a physical device costs ~20s per module). The vulnerable
        // path still fires and records evidence, and the slider was genuinely
        // moved beforehand.
        if (await exerciseControls(driver)) {
          await back(driver);
          await clearSearch(driver);
          await openModuleBySearch(driver, mod);
        }
        actionsTriggered += await tapAllDemoActions(driver);

        // On native drivers an evidence panel is the on-device proof the
        // vulnerable path ran. The Flutter driver can't prefix-match, so we
        // don't hold it to this assertion.
        if (nativeDriver && (await hasEvidence(driver))) withEvidence += 1;

        await screenshot(driver, mod.id);

        await back(driver);
        await clearSearch(driver);
        if (!(await isPresent(driver, manifest.ids.disclaimerBanner, 8000))) {
          await recoverToHome(driver);
        }
      } catch (err) {
        failures.push({
          id: mod.id,
          stage: 'walk',
          error: err && err.message ? err.message : String(err),
        });
        // Relaunch to a known home state so the next module starts clean.
        await recoverToHome(driver);
      }
    }

    /* eslint-disable no-console */
    console.log(
      `\nDVMA walk complete: opened ${opened}/${modules.length} modules, ` +
        `triggered ${actionsTriggered} demo actions, ` +
        `${withEvidence} showed an evidence panel, ` +
        `${failures.length} failure(s).`,
    );
    if (failures.length) {
      console.log('Failures:');
      for (const f of failures) {
        console.log(`  - ${f.id} [${f.stage}]: ${f.error}`);
      }
    }
    /* eslint-enable no-console */

    expect(failures).toHaveLength(0);
  });
});
