import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'native_channel.dart';

/// Bridge to DVMA's native `dvma/native_memory` channel (see NativeMemoryProbe.kt
/// + cpp/dvma_native_memory.c on Android; DvmaNativeProbes.swift +
/// Runner/dvma_native_memory.c on iOS).
///
/// `unsafeCopy` invokes a real compiled C `strcpy` into a fixed 16-byte stack
/// buffer with no bounds check (native_code_memory_bugs, CWE-120 / CWE-787), so
/// the memory bug lives in the native binary (libdvma_native.so on Android, the
/// Runner Mach-O on iOS), not in Dart. Returns the C-side report, or null on
/// other platforms (the module then falls back to its offline model so the demo
/// still runs under `flutter test`).
class NativeMemoryBridge {
  const NativeMemoryBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/native_memory');

  static bool get isAvailable => Platform.isAndroid || Platform.isIOS;

  /// Runs the real native strcpy over [input]; the returned report states
  /// whether the adjacent canary slot was clobbered.
  static Future<String?> unsafeCopy(String input) =>
      invokeNativeString(_channel, isAvailable, 'unsafeCopy', {'input': input});
}
