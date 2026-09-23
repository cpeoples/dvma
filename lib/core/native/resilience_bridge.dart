import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'native_channel.dart';

/// Bridge to DVMA's native `dvma/resilience` channel (see ResilienceProbe.kt).
///
/// The resilience modules use this to run a *real* on-device check (root/su
/// binaries, frida in /proc/self/maps + port probe, emulator Build markers, the
/// debugger flag, the signing certificate hash) rather than a pure-Dart
/// simulation. Each method returns the raw native finding string.
///
/// On non-Android/iOS platforms (desktop/unit tests) every method returns null,
/// so the caller falls back to its in-app model and the demos still work
/// everywhere. On Android the probe is a real Kotlin check; on iOS it is a real
/// Swift check (see ios/Runner/DvmaNativeProbes.swift: jailbreak markers,
/// sysctl P_TRACED, simulator env, dyld Frida-image scan + port 27042, embedded
/// profile digest). The point of the modules is that the native signal is real
/// but the app still gates on a bypassable client-side boolean.
class ResilienceBridge {
  const ResilienceBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/resilience');

  static bool get isAvailable => Platform.isAndroid || Platform.isIOS;

  static Future<String?> _invoke(String method) =>
      invokeNativeString(_channel, isAvailable, method);

  /// Real root/su-binary/test-keys/root-package findings, or null off-Android.
  static Future<String?> rootCheck() => _invoke('rootCheck');

  /// Real frida /proc/self/maps + port-27042 findings, or null off-Android.
  static Future<String?> fridaCheck() => _invoke('fridaCheck');

  /// Real emulator Build-field findings, or null off-Android.
  static Future<String?> emulatorCheck() => _invoke('emulatorCheck');

  /// Real debugger-connected / FLAG_DEBUGGABLE findings, or null off-Android.
  static Future<String?> debuggerCheck() => _invoke('debuggerCheck');

  /// Real signing-certificate SHA-256 digest, or null off-Android.
  static Future<String?> tamperCheck() => _invoke('tamperCheck');

  /// Real installed-package enumeration screened against a known-hostile
  /// catalog (malware_detection_absent), or null off-Android.
  static Future<String?> installedPackages() => _invoke('installedPackages');

  /// Real app-virtualization / cloning-container indicators (work-profile uid,
  /// duplicate/non-standard data paths), or null off-Android.
  static Future<String?> virtualizationCheck() =>
      _invoke('virtualizationCheck');
}
