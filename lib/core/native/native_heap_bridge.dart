import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'native_channel.dart';

/// Bridge to DVMA's native `dvma/native_heap` channel (see NativeHeapProbe.kt
/// + the tail of cpp/dvma_native_memory.c).
///
/// `useAfterFree` invokes a real compiled C routine that frees a heap record,
/// keeps using it through the dangling pointer, then frees it again
/// (native_code_memory_bugs, CWE-416 / CWE-415). This is a second real native
/// memory bug alongside the stack strcpy overflow, a heap use-after-free +
/// double free in libdvma_native.so, inspectable with ghidra/gdb/frida, not a
/// Dart model. Returns the C-side report, or null off Android (no Swift
/// equivalent yet), so the module keeps its existing behaviour under
/// `flutter test`.
class NativeHeapBridge {
  const NativeHeapBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/native_heap');

  // Android-only: implemented in the NDK library, no iOS Swift equivalent.
  static bool get isAvailable => Platform.isAndroid;

  /// Runs the real native use-after-free; when [writeAfterFree] is true it also
  /// writes through the dangling pointer before the double free.
  static Future<String?> useAfterFree({bool writeAfterFree = true}) =>
      invokeNativeString(_channel, isAvailable, 'useAfterFree', {
        'writeAfterFree': writeAfterFree,
      });
}
