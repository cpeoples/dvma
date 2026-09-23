import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'native_channel.dart';

/// Bridge to DVMA's native `dvma/native_proximity` channel (see
/// NativeProximityProbe.kt + cpp/dvma_native_proximity.c).
///
/// `parseTlv` invokes a real compiled C TLV parser that copies a pre-auth
/// proximity payload using the attacker-declared length field, never bounded by
/// the bytes actually received (proximity_transfer_unsafe_parsing, CWE-125 /
/// CWE-787). A length-lie over-reads adjacent heap in libdvma_native.so, the
/// AirDrop / Quick Share over-read class, not in Dart. Returns the C-side
/// report (including a slice of what leaked), or null off Android (no Swift
/// equivalent yet), so the module falls back to its offline Dart model and the
/// demo still runs under `flutter test`.
class NativeProximityBridge {
  const NativeProximityBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/native_proximity');

  // Android-only: implemented in the NDK library, no iOS Swift equivalent.
  static bool get isAvailable => Platform.isAndroid;

  /// Runs the real native TLV parse with [declaredLen] trusted over the
  /// [payloadLen] actually received; the report states how many bytes leaked.
  static Future<String?> parseTlv({
    required int declaredLen,
    required int payloadLen,
  }) => invokeNativeString(_channel, isAvailable, 'parseTlv', {
    'declaredLen': declaredLen,
    'payloadLen': payloadLen,
  });
}
