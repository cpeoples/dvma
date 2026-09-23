// test/smoke.e2e.js
//
// Minimal DVMA smoke test: the app launches, the home index renders (the
// intentionally-vulnerable disclaimer banner is present), and the search field
// is usable. Runs against either driver flavor (Flutter or native) unchanged.

import { expect } from '@wdio/globals';
import {
  loadManifest,
  waitForId,
  isPresent,
  findById,
  enterText,
  clearSearch,
  isFlutterSession,
} from '../lib/dvma.js';

const manifest = loadManifest();

describe('DVMA smoke', () => {
  it('launches and renders the home index', async () => {
    // The disclaimer banner is the top-of-home marker that the app booted.
    await waitForId(driver, manifest.ids.disclaimerBanner, 30000);
    expect(await isPresent(driver, manifest.ids.disclaimerBanner)).toBe(true);

    // The flavor badge should also be present in the app bar.
    expect(await isPresent(driver, manifest.ids.flavorBadge)).toBe(true);
  });

  it('supports searching via the search field', async () => {
    const search = await waitForId(driver, manifest.ids.searchField, 15000);

    // Type a query that should match at least one known module title/id. Uses
    // the flavor-agnostic entry helper (native XCUITest on a Flutter TextField
    // can lack keyboard focus, so it retries via keys()).
    await search.click();
    await enterText(driver, search, 'storage');

    // After filtering, the home list is still alive (disclaimer present) and,
    // on native drivers that expose the value, the field kept our input.
    if (!isFlutterSession(driver)) {
      const value = await search.getText().catch(() => '');
      if (value) expect(value.toLowerCase()).toContain('storage');
    }

    expect(await isPresent(driver, manifest.ids.disclaimerBanner)).toBe(true);

    // Clear the query so subsequent specs start from the full list.
    await clearSearch(driver);
    await findById(driver, manifest.ids.searchField);
  });
});
