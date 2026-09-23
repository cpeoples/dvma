// wdio.android.conf.js
//
// Android capabilities for the DVMA automation suite.
//
// Two driver flavors are supported; select with the DVMA_DRIVER env var:
//   DVMA_DRIVER=flutter  (default)  -> appium-flutter-driver, finds ValueKeys
//   DVMA_DRIVER=native              -> UiAutomator2, finds Semantics resource-ids
//
// Build the DVMA "full" APK first (all enabled modules):
//   flutter build apk --debug --dart-define-from-file=config/flavors/full.json
// The debug APK lands at:
//   build/app/outputs/flutter-apk/app-debug.apk
//
// NOTE: appium-flutter-driver requires a Flutter build that includes the Dart
// VM service extension - i.e. a DEBUG or PROFILE build, NOT a stripped release.
// The native (UiAutomator2) flavor works against any build, including release.
//
// Env vars (all optional; sensible defaults shown):
//   APP_PATH        absolute path to the .apk to install & test
//   APP_PACKAGE     Android applicationId (default com.dvma)
//   APP_ACTIVITY    launch activity (default .MainActivity)
//   DEVICE_NAME     emulator/device name (default "Android Emulator")
//   PLATFORM_VERSION Android version, e.g. "14"
//   UDID            specific device serial (from `adb devices`)

import path from 'node:path';
import { sharedConfig, driverFlavor } from './wdio.shared.conf.js';

const APP_PATH =
  process.env.APP_PATH ||
  path.resolve(
    process.cwd(),
    '..',
    '..',
    'build',
    'app',
    'outputs',
    'flutter-apk',
    'app-debug.apk',
  );

const APP_PACKAGE = process.env.APP_PACKAGE || 'com.dvma';
const APP_ACTIVITY = process.env.APP_ACTIVITY || '.MainActivity';

const common = {
  platformName: 'Android',
  'appium:deviceName': process.env.DEVICE_NAME || 'Android Emulator',
  'appium:app': APP_PATH,
  'appium:appPackage': APP_PACKAGE,
  'appium:appActivity': APP_ACTIVITY,
  'appium:autoGrantPermissions': true,
  'appium:newCommandTimeout': 300,
  // Don't reset between the smoke and walk specs in a single run.
  'appium:noReset': false,
};

if (process.env.PLATFORM_VERSION) {
  common['appium:platformVersion'] = process.env.PLATFORM_VERSION;
}
if (process.env.UDID) {
  common['appium:udid'] = process.env.UDID;
}

const flavor = driverFlavor();

const capabilities =
  flavor === 'native'
    ? [
        {
          ...common,
          // Native UiAutomator2: locate by resource-id / accessibility id.
          'appium:automationName': 'UiAutomator2',
        },
      ]
    : [
        {
          ...common,
          // appium-flutter-driver: locate by Flutter ValueKey.
          'appium:automationName': 'Flutter',
          // Let the driver auto-discover the Dart VM service port.
          'appium:retryBackoffTime': 500,
        },
      ];

export const config = {
  ...sharedConfig,
  capabilities,
};
