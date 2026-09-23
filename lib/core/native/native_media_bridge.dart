import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'native_channel.dart';

/// Bridge to DVMA's native `dvma/native_media` channel (see NativeMediaProbe.kt
/// + cpp/dvma_native_media.c).
///
/// `decodeUnsafe` invokes a real compiled C decoder that sizes a pixel buffer
/// with a 32-bit `width * height * bpp` multiply (unsafe_media_decoding,
/// CWE-190 -> CWE-122): attacker-declared dimensions wrap the multiply, so
/// malloc returns an undersized chunk while the decode loop writes the real
/// 64-bit pixel count, a genuine integer-overflow heap buffer overflow in
/// libdvma_native.so, not in Dart. Returns the C-side report, or null off
/// Android (no Swift equivalent yet), so the module falls back to its offline
/// Dart model and the demo still runs under `flutter test`.
class NativeMediaBridge {
  const NativeMediaBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/native_media');

  // Android-only: the vulnerable decoder is implemented in the NDK library.
  // There is no iOS Swift implementation, so off-Android callers fall back to
  // the offline Dart model.
  static bool get isAvailable => Platform.isAndroid;

  /// Runs the real native decode for the attacker-declared header; the report
  /// states the wrapped alloc size vs the bytes actually written.
  static Future<String?> decodeUnsafe({
    required int width,
    required int height,
    required int bpp,
  }) => invokeNativeString(_channel, isAvailable, 'decodeUnsafe', {
    'width': width,
    'height': height,
    'bpp': bpp,
  });
}
