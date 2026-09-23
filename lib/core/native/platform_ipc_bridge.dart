import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'native_channel.dart';

/// Bridge to DVMA's native `dvma/platform_ipc` channel (see PlatformIpc.kt).
///
/// The PendingIntent / notification / overlay / widget / dynamic-code /
/// accessibility modules use this to drive DVMA's real Android platform
/// surfaces in-process (post a mutable PendingIntent in a real Notification,
/// load code via DexClassLoader from an app-writable file, etc.) and to read
/// back the effect the native op recorded in the native EvidenceStore, keyed by
/// the module's vuln id.
///
/// On non-Android platforms every call returns null and the caller falls back
/// to its in-app (in-memory) model, so the demos still work under `flutter
/// test` and on iOS/desktop.
class PlatformIpcBridge {
  const PlatformIpcBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/platform_ipc');

  static bool get isAvailable => Platform.isAndroid;

  static Future<String?> _invoke(String method, [Map<String, Object?>? args]) =>
      invokeNativeString(_channel, isAvailable, method, args);

  /// mcp_open_url_arbitrary_intent / ai_output_to_intent_url: fire a real
  /// implicit ACTION_VIEW (Android) / UIApplication.open (iOS) for an
  /// attacker/model-chosen [url] with no scheme allowlist, so a non-web scheme
  /// launches another app. Available on Android + iOS (the channel handles
  /// this one method on both); null elsewhere.
  static Future<String?> launchExternalUrl(String url) => invokeNativeString(
    _channel,
    Platform.isAndroid || Platform.isIOS,
    'launchExternalUrl',
    {'url': url},
  );

  /// Read back the effect a native op recorded for [key] (a vuln id), or null
  /// if nothing has been applied / the channel is unavailable.
  static Future<String?> applied(String key) =>
      _invoke('applied', {'key': key});

  /// pending_intent_hijacking / pendingintent_provenance_confusion: post a real
  /// mutable+implicit PendingIntent inside a Notification (dumpsys observable).
  static Future<String?> postMutablePendingIntent() =>
      _invoke('postMutablePendingIntent');

  /// push_notification_leakage: post a real Notification whose ticker/extras
  /// carry sensitive content (visible on the lockscreen / to listeners).
  static Future<String?> postSensitiveNotification() =>
      _invoke('postSensitiveNotification');

  /// overlay_phishing / tapjacking: report the real SYSTEM_ALERT_WINDOW /
  /// overlay-config gap the app leaves open.
  static Future<String?> overlayConfigGap() => _invoke('overlayConfigGap');

  /// background_activity_launch_abuse: attempt a real background startActivity.
  static Future<String?> backgroundActivityLaunch() =>
      _invoke('backgroundActivityLaunch');

  /// dynamic_code_loading_rce: DexClassLoader over an app-writable file, then
  /// reflectively invoke the loaded (unverified) code.
  static Future<String?> dynamicCodeLoad() => _invoke('dynamicCodeLoad');

  /// remoteviews_widget_action_injection: build the real RemoteViews payload a
  /// widget host inflates, posted with a mutable PendingIntent.
  static Future<String?> postRemoteViewsWidget() =>
      _invoke('postRemoteViewsWidget');

  /// accessibility_service_privilege_abuse / notification_listener_*: report the
  /// real declared-but-unguarded AccessibilityService / listener state.
  static Future<String?> accessibilityServiceState() =>
      _invoke('accessibilityServiceState');

  /// exported_component_state_manipulation: post two real Notifications, then
  /// have the exported StateControlActivity cancel the victim by id in-process.
  static Future<String?> stateManipulation() => _invoke('stateManipulation');

  /// missing_flag_secure / predictive_back_leakage: report the real window
  /// FLAG_SECURE / recents-screenshot posture of DVMA's own window.
  static Future<String?> flagSecureState() => _invoke('flagSecureState');
}
