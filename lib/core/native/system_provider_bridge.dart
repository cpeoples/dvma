import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'native_channel.dart';

/// Bridge to DVMA's native `dvma/system_provider` channel (see
/// SystemProviderProbe.kt).
///
/// The `system_provider` modules use this to perform a real on-device
/// query/config against the actual OS capability they teach, DevicePolicyManager,
/// the Settings.Secure enabled-provider lists (IMEs / accessibility services /
/// notification listeners), MediaProjectionManager, VpnService consent,
/// CompanionDeviceManager associations, and a real world-readable-ish shared
/// file, instead of a pure-Dart in-memory simulation. Each method returns the
/// raw native finding string.
///
/// Many of these capabilities cannot be fully ARMED without a user grant a lab
/// cannot auto-provision (enabling an accessibility service, approving a
/// MediaProjection token, confirming a VPN consent, picking a companion device,
/// enabling the custom IME). For those the native probe reports the real current
/// grant/config state plus what enabling the capability would expose, so the
/// module is genuinely device-observable.
///
/// On non-Android platforms (iOS/desktop/unit tests) every method returns null,
/// so the caller falls back to its in-app model and the demos still work
/// everywhere / `flutter test` still passes.
class SystemProviderBridge {
  const SystemProviderBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/system_provider');

  static bool get isAvailable => Platform.isAndroid;

  static Future<String?> _invoke(String method, [Map<String, Object?>? args]) =>
      invokeNativeString(_channel, isAvailable, method, args);

  /// Real DevicePolicyManager posture (isAdminActive / activeAdmins /
  /// isDeviceOwner / isProfileOwner), or null off-Android.
  static Future<String?> devicePolicyState() => _invoke('devicePolicyState');

  /// Real enabled privileged providers via Settings.Secure (enabled IMEs /
  /// accessibility services / notification listeners), or null off-Android.
  static Future<String?> enabledProviders() => _invoke('enabledProviders');

  /// Real MediaProjectionManager availability + token-reuse gap, or null
  /// off-Android.
  static Future<String?> mediaProjectionState() =>
      _invoke('mediaProjectionState');

  /// Real VpnService.prepare() consent state + trust-anchor gap, or null
  /// off-Android.
  static Future<String?> vpnConsentState() => _invoke('vpnConsentState');

  /// Real CompanionDeviceManager associations + over-broad-capability gap, or
  /// null off-Android.
  static Future<String?> companionAssociations() =>
      _invoke('companionAssociations');

  /// FULLY real: write [value] under [key] into a real shared external-files
  /// directory as the "main app" member and read it back as a different member.
  /// Returns the leaked absolute path + contents, or null off-Android.
  static Future<String?> sharedContainerLeak(String key, String value) =>
      _invoke('sharedContainerLeak', {'key': key, 'value': value});

  /// custom_signature_permission_squatting: real PackageManager protection
  /// level of DVMA's custom ADMIN_OP permission + runtime checkPermission.
  static Future<String?> checkCustomPermission() =>
      _invoke('checkCustomPermission');

  /// photo_picker_over_access: real MediaStore query enumerating on-device
  /// images (full-library over-collection) + media permission state.
  static Future<String?> mediaStoreQuery() => _invoke('mediaStoreQuery');

  /// platform_version_security_fallback: real Build.VERSION.SDK_INT + a genuine
  /// StrongBox Keystore attempt (catches StrongBoxUnavailableException).
  static Future<String?> platformVersionKeystore() =>
      _invoke('platformVersionKeystore');

  /// telephony_capability_abuse: real ACTION_CALL intent resolution + CALL_PHONE
  /// runtime permission state (the device-observable missing per-invocation
  /// check).
  static Future<String?> telephonyCapability({String? number}) =>
      _invoke('telephonyCapability', {'number': number});
}
