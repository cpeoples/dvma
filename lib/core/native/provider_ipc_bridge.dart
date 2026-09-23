import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'native_channel.dart';

/// Bridge to DVMA's native `dvma/provider_ipc` channel (see ProviderIpc.kt).
///
/// The exported-ContentProvider modules use this to drive DVMA's real, exported
/// [VulnerableProvider] in-process through the app's own ContentResolver -
/// exercising the same code path drozer / `adb shell content` / a companion app
/// hit cross-process, and to read back the effect the provider recorded in the
/// native EvidenceStore, keyed by the module's vuln id.
///
/// On non-Android platforms every call returns null and the caller falls back
/// to its in-app (in-memory / dart:io) model, so the demos still work under
/// `flutter test` and on iOS/desktop.
class ProviderIpcBridge {
  const ProviderIpcBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/provider_ipc');

  static bool get isAvailable => Platform.isAndroid;

  /// Read back the effect the provider recorded for [key] (a vuln id), or null
  /// if nothing has been applied / the channel is unavailable.
  static Future<String?> applied(String key) =>
      _invoke('applied', {'key': key});

  /// content_provider_sql_injection: run a real query() through the resolver,
  /// passing [selection] unbound so the provider concatenates it into SQL.
  /// Returns the leaked rows (incl. the secret column) or null off-Android.
  static Future<String?> sqlInject(String selection) =>
      _invoke('sqlInject', {'selection': selection});

  /// incoming_call_metadata_missing_authorization: read `content://.../calls`
  /// through the app's own ContentResolver. The provider returns the call-log
  /// row with no permission check; returns the leaked metadata or null
  /// off-Android.
  static Future<String?> callLog() => _invoke('callLog', const {});

  /// *_path_traversal / content_uri_resolver_confused_deputy: open
  /// `content://.../files/<name>` through the app's own ContentResolver. A
  /// `../session.token` name escapes the export dir; returns the bytes read.
  static Future<String?> openTraversal(String name) =>
      _invoke('openTraversal', {'name': name});

  /// grant_uri_permission_abuse / clipdata_uri_grant_leakage /
  /// persistable_uri_grant_abuse / file_descriptor_capability_leakage: perform
  /// the real grantor-side URI-grant ops (Intent grant flags + ClipData grant +
  /// grantUriPermission + takePersistableUriPermission) for [uri], returning a
  /// description of the leaked grant.
  static Future<String?> grantUri([String? uri]) =>
      _invoke('grantUri', {'uri': uri});

  static Future<String?> _invoke(String method, Map<String, Object?> args) =>
      invokeNativeString(_channel, isAvailable, method, args);
}
