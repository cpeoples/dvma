import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'native_channel.dart';

/// Bridge to DVMA's native `dvma/app_intent` channel (see
/// DvmaLockscreenIntents.swift + DvmaNativeProbes.swift).
///
/// iOS backs lockscreen_control_action_authorization /
/// assistant_locked_device_capability_abuse with real `AppIntent`s compiled
/// into the Runner binary. `invokeSensitiveIntent` runs the vulnerable
/// `UnlockFrontDoorIntent.perform()` (which declares no authentication policy)
/// and returns a report of its declared policy vs. the secure intent plus the
/// live device lock state. Returns null off-iOS so the caller keeps its
/// deterministic model.
class AppIntentBridge {
  const AppIntentBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/app_intent');

  static bool get isAvailable => Platform.isIOS;

  /// Runs the real sensitive App Intent and returns the native report.
  static Future<String?> invokeSensitiveIntent() =>
      invokeNativeString(_channel, isAvailable, 'invokeSensitiveIntent');

  /// app_intent_parameter_authorization: run the real parameterized
  /// ExportAccountIntent with an attacker-supplied [accountId].
  static Future<String?> invokeExportIntent(String accountId) =>
      invokeNativeString(_channel, isAvailable, 'invokeExportIntent', {
        'accountId': accountId,
      });

  /// system_surface_privileged_appintent_exposure: report the real system
  /// surfaces the app's App Intents are exposed to (from compiled metadata).
  static Future<String?> intentSurfaces() =>
      invokeNativeString(_channel, isAvailable, 'intentSurfaces');
}
