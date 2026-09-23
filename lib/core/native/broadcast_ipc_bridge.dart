import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'native_channel.dart';

/// Bridge to DVMA's native `dvma/broadcast_ipc` channel (see BroadcastIpc.kt).
///
/// Broadcast IPC modules use this to cross a process boundary on
/// Android. On other platforms every method returns null and the caller falls
/// back to its in-app model, so the demos still work in tests / on iOS.
class BroadcastIpcBridge {
  const BroadcastIpcBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/broadcast_ipc');

  static bool get isAvailable => Platform.isAndroid;

  /// Read back what DVMA's exported receiver applied for [action] (the extras a
  /// sender delivered). Used by the receive-side modules.
  static Future<String?> applied(String action) =>
      _invoke('applied', {'action': action});

  /// implicit_intent_sensitive_data: emit sensitive extras on an implicit
  /// intent (any matching app receives) or explicitly to DVMA's package.
  static Future<String?> broadcastImplicitSensitive(
    Map<String, String> extras,
  ) => _invoke('broadcastImplicitSensitive', {'extras': extras});
  static Future<String?> broadcastExplicitSensitive(
    Map<String, String> extras,
  ) => _invoke('broadcastExplicitSensitive', {'extras': extras});

  /// ordered_broadcast_result_injection: send an ordered broadcast whose result
  /// a higher-priority receiver may rewrite; the guarded form requires the
  /// signature permission.
  static Future<String?> sendOrdered(String seed) =>
      _invoke('sendOrdered', {'seed': seed});
  static Future<String?> sendOrderedGuarded(String seed) =>
      _invoke('sendOrderedGuarded', {'seed': seed});

  /// default_role_holder_confusion: delegate a secret to the resolved "default"
  /// role holder via an implicit broadcast.
  static Future<String?> delegateRole(String secret) =>
      _invoke('delegateRole', {'secret': secret});

  /// android_capability_composition_chain: fire the real exported
  /// ChainEntryReceiver so the mutable-PI -> receiver -> service -> transfer
  /// chain runs end-to-end in-process, then read back the sink's outcome.
  static Future<String?> fireChain({String? amount, String? to}) =>
      _invoke('fireChain', {'amount': amount, 'to': to});

  static Future<String?> _invoke(String method, Map<String, Object?> args) =>
      invokeNativeString(_channel, isAvailable, method, args);
}
