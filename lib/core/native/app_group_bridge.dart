import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'native_channel.dart';

/// Bridge to DVMA's native `dvma/app_group` channel, the real iOS App Group
/// shared-container probe (see ios/Runner/DvmaNativeProbes.swift).
///
/// This is the iOS-native counterpart to the Android `sharedContainerLeak`
/// (SystemProviderProbe.kt). On iOS the probe obtains the App Group shared
/// container via `containerURL(forSecurityApplicationGroupIdentifier:)` and
/// performs a genuine cross-"member" write→read of a real file inside it, the
/// amplification the `app_group_shared_container_amplification` module teaches.
///
/// `containerURL(...)` only returns a container when the app is code-signed with
/// the matching `com.apple.security.application-groups` entitlement (see
/// ios/Runner/Runner.entitlements) AND a provisioning profile that includes the
/// group. On an unentitled/unsigned build (the default repo/simulator build) the
/// native probe returns `detected=false reason=entitlement-missing …` rather than
/// faking a finding, and the module falls back to its deterministic in-app
/// simulation, so the demo works everywhere while staying honest.
///
/// Android has its own real path via `SystemProviderBridge.sharedContainerLeak`,
/// so this bridge is iOS-only; on Android/desktop/tests it returns null.
class AppGroupBridge {
  const AppGroupBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/app_group');

  /// iOS-only: the real App Group container path exists only on iOS.
  static bool get isAvailable => Platform.isIOS;

  static Future<String?> _invoke(String method, [Map<String, Object?>? args]) =>
      invokeNativeString(_channel, isAvailable, method, args);

  /// Real on an App-Group-entitled iOS build: write [value] under [key] into the
  /// shared container as the "main app" member and read it back as a low-trust
  /// "keyboard extension" member. Returns the leaked absolute path + contents (or
  /// an honest `entitlement-missing` reason), or null off-iOS.
  static Future<String?> sharedContainerLeak(String key, String value) =>
      _invoke('sharedContainerLeak', {'key': key, 'value': value});
}
