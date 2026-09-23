// wdio.ios.conf.js
//
// iOS capabilities for the DVMA automation suite.
//
// Two driver flavors are supported; select with the DVMA_DRIVER env var:
//   DVMA_DRIVER=flutter  (default)  -> appium-flutter-driver, finds ValueKeys
//   DVMA_DRIVER=native              -> XCUITest, finds Semantics accessibilityIds
//
// Build the DVMA "full" app for the simulator first (all enabled modules):
//   flutter build ios --debug --simulator \
//     --dart-define-from-file=config/flavors/full.json
// The .app bundle lands at:
//   build/ios/iphonesimulator/Runner.app
//
// The one-shot harness automation/scripts/appium_run_ios.sh does the whole
// flow (boot sim, build, start Appium, run the walk, collect artifacts).
//
// NOTE: appium-flutter-driver requires a Flutter build that includes the Dart
// VM service extension - i.e. a DEBUG or PROFILE build, NOT a stripped release.
// The native (XCUITest) flavor works against any build.
//
// Env vars (all optional; sensible defaults shown):
//   APP_PATH         absolute path to the .app (simulator) or .ipa (device)
//   BUNDLE_ID        iOS bundle identifier (default com.dvma)
//   UDID             specific simulator/device UDID (from `xcrun simctl list`);
//                    when set, deviceName/platformVersion are ignored
//   DEVICE_NAME      simulator name when no UDID given (default "iPhone 17")
//   PLATFORM_VERSION iOS version, e.g. "17.5" (only used when no UDID given)

import path from 'node:path';
import { sharedConfig, driverFlavor } from './wdio.shared.conf.js';

// Real-device mode is selected by the harness (appium_run_ios.sh) via DEVICE=1.
// On a physical iPad the app bundle is a device build (iphoneos, signed) and
// XCUITest must (re)sign its WebDriverAgent with your team; on the Simulator no
// signing is involved. Everything else - the walk spec, ids, flow - is shared.
const IS_DEVICE = process.env.DEVICE === '1';

const APP_PATH =
  process.env.APP_PATH ||
  path.resolve(
    process.cwd(),
    '..',
    '..',
    'build',
    'ios',
    IS_DEVICE ? 'iphoneos' : 'iphonesimulator',
    'Runner.app',
  );

const BUNDLE_ID = process.env.BUNDLE_ID || 'com.dvma';

const common = {
  platformName: 'iOS',
  'appium:app': APP_PATH,
  'appium:bundleId': BUNDLE_ID,
  'appium:autoAcceptAlerts': true,
  'appium:newCommandTimeout': 300,
  'appium:noReset': false,
};

// A specific UDID (the harness always passes one for both sim and device)
// pins XCUITest to that exact target; deviceName/platformVersion are only hints
// used when no UDID is given.
if (process.env.UDID) {
  common['appium:udid'] = process.env.UDID;
} else {
  common['appium:deviceName'] = process.env.DEVICE_NAME || 'iPhone 17';
  if (process.env.PLATFORM_VERSION) {
    common['appium:platformVersion'] = process.env.PLATFORM_VERSION;
  }
}

// Physical devices need WebDriverAgent signed for your team. The harness passes
// XCODE_ORG_ID (Apple Team ID) and an optional WDA bundle id prefix so WDA gets
// a unique, signable id under your account.
if (IS_DEVICE) {
  if (process.env.XCODE_ORG_ID) {
    common['appium:xcodeOrgId'] = process.env.XCODE_ORG_ID;
    common['appium:xcodeSigningId'] = process.env.XCODE_SIGNING_ID || 'Apple Development';
  }
  if (process.env.WDA_BUNDLE_ID) {
    common['appium:updatedWDABundleId'] = process.env.WDA_BUNDLE_ID;
  }
  // Surface the underlying xcodebuild output when WDA fails to build/sign
  // (code 65 is almost always a provisioning/signing problem).
  if (process.env.SHOW_XCODE_LOG === '1') {
    common['appium:showXcodeLog'] = true;
  }
  // Reuse a previously built+signed WDA across runs so we don't re-sign every
  // time (much faster, and avoids the free-account cert churn). Opt-in.
  if (process.env.USE_PREBUILT_WDA === '1') {
    common['appium:usePrebuiltWDA'] = true;
  }
}

const flavor = driverFlavor();

const capabilities =
  flavor === 'native'
    ? [
        {
          ...common,
          // Native XCUITest: locate by accessibilityIdentifier / accessibility id.
          'appium:automationName': 'XCUITest',
        },
      ]
    : [
        {
          ...common,
          // appium-flutter-driver: locate by Flutter ValueKey.
          'appium:automationName': 'Flutter',
          'appium:retryBackoffTime': 500,
        },
      ];

export const config = {
  ...sharedConfig,
  capabilities,
};
