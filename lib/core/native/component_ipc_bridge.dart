import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'native_channel.dart';

/// Bridge to DVMA's native `dvma/component_ipc` channel (see ComponentIpc.kt).
///
/// The exported-component modules use this to read back what one of DVMA's
/// exported Activities/Services applied on behalf of a separate app's caller,
/// keyed by the module's vuln id. On non-Android platforms it returns null and
/// the caller falls back to its in-app model, so the demos still work in tests
/// / on iOS.
class ComponentIpcBridge {
  const ComponentIpcBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/component_ipc');

  static bool get isAvailable => Platform.isAndroid;

  static Future<String?> _invoke(String method, [Map<String, Object?>? args]) =>
      invokeNativeString(_channel, isAvailable, method, args);

  /// Read back the effect an exported component recorded for [key] (a vuln id),
  /// or null if nothing has been applied / the channel is unavailable.
  static Future<String?> applied(String key) =>
      _invoke('applied', {'key': key});

  /// exported_android_components: start the real exported AdminActivity
  /// in-process and read back the caller it recorded.
  static Future<String?> startAdminActivity() => _invoke('startAdminActivity');

  /// activity_alias_exposure: reach the not-exported ProtectedAdminActivity via
  /// the exported activity-alias.
  static Future<String?> startViaAlias() => _invoke('startViaAlias');

  /// exported_component_arbitrary_url_activity: start UrlDispatchActivity with
  /// attacker-named target/activity extras.
  static Future<String?> startUrlDispatch({String? target, String? activity}) =>
      _invoke('startUrlDispatch', {'target': target, 'activity': activity});

  /// intent_arg_injection_rce: start LauncherActivity with a `cmd` extra.
  static Future<String?> startLauncher({String? cmd}) =>
      _invoke('startLauncher', {'cmd': cmd});

  /// confused_deputy_intent_validation: start DeputyActivity naming only the
  /// privileged action string.
  static Future<String?> startDeputy({String? setting}) =>
      _invoke('startDeputy', {'setting': setting});

  /// intent_redirection: start the exported ProxyActivity with a nested forward
  /// Intent targeting the internal-only InternalAdminActivity.
  static Future<String?> startRedirection() => _invoke('startRedirection');

  /// activity_task_stack_hijacking: start the shared-taskAffinity
  /// HijackTargetActivity (dumpsys-observable).
  static Future<String?> startTaskHijackTarget() =>
      _invoke('startTaskHijackTarget');

  /// privileged_service_binding_exposure: bind the real exported
  /// PrivilegedService in-process and invoke its Binder method.
  static Future<String?> bindPrivilegedService() =>
      _invoke('bindPrivilegedService');
}
