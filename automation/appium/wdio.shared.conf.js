// wdio.shared.conf.js
//
// Base WebdriverIO configuration shared by the Android and iOS configs.
// Platform-specific configs spread this and add `capabilities`.
//
// Appium must be running/available. By default WebdriverIO talks to a local
// Appium server at http://127.0.0.1:4723. Start one with `appium` in another
// terminal, or set `services: ['appium']` and install `@wdio/appium-service`.

export const sharedConfig = {
  runner: 'local',

  // Appium server connection. Override via APPIUM_HOST / APPIUM_PORT if needed.
  hostname: process.env.APPIUM_HOST || '127.0.0.1',
  port: Number(process.env.APPIUM_PORT || 4723),
  path: process.env.APPIUM_PATH || '/',

  specs: ['./test/**/*.e2e.js'],

  maxInstances: 1,
  logLevel: process.env.WDIO_LOG_LEVEL || 'info',
  bail: 0,
  waitforTimeout: 15000,
  connectionRetryTimeout: 180000,
  connectionRetryCount: 2,

  framework: 'mocha',
  reporters: ['spec'],
  mochaOpts: {
    ui: 'bdd',
    // The walk-all-modules spec exercises every module in one test case. On a
    // physical device each module costs several seconds (search, open, actions,
    // recover), so the whole walk can run ~45 min; the Simulator is faster.
    // Override for a subset run with MOCHA_TIMEOUT.
    timeout: Number(process.env.MOCHA_TIMEOUT || 60 * 60 * 1000),
  },
};

/**
 * Read the desired driver flavor from the DVMA_DRIVER env var.
 *   - 'flutter' (default) -> appium-flutter-driver (find by ValueKey)
 *   - 'native'            -> UiAutomator2 / XCUITest (find by accessibility id)
 * @returns {'flutter'|'native'}
 */
export function driverFlavor() {
  const v = (process.env.DVMA_DRIVER || 'flutter').toLowerCase();
  return v === 'native' ? 'native' : 'flutter';
}
