import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'native_channel.dart';

/// Bridge to DVMA's native `dvma/native_callmedia` channel (see
/// NativeCallMediaProbe.kt + cpp/dvma_native_callmedia.c).
///
/// `parseOnRing` invokes a real compiled C parser that reassembles a call-setup
/// frame into a fixed heap arena WHILE THE CALL IS RINGING and reads the
/// attacker-declared length out of it, never bounded by the bytes actually
/// received (zero_click_call_media_parse_sink, CWE-125). A length-lie
/// over-reads adjacent arena memory in libdvma_native.so, the WeWorm
/// zero-click VoIP surface at higher fidelity than the Dart Uint8List model.
/// Returns the C-side report (including the leaked slice), or null off Android
/// (no Swift equivalent yet), so the module falls back to its offline Dart
/// model and the demo still runs under `flutter test`.
class NativeCallMediaBridge {
  const NativeCallMediaBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/native_callmedia');

  // Android-only: implemented in the NDK library, no iOS Swift equivalent.
  static bool get isAvailable => Platform.isAndroid;

  /// Runs the real native ring-time parse with [declaredLen] trusted over the
  /// [receivedLen] payload; the report states how many bytes were over-read.
  static Future<String?> parseOnRing({
    required int declaredLen,
    required int receivedLen,
  }) => invokeNativeString(_channel, isAvailable, 'parseOnRing', {
    'declaredLen': declaredLen,
    'receivedLen': receivedLen,
  });
}
