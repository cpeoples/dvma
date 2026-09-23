import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import '../../../core/native/native_channel.dart';

/// Dart side of the cross-app OTP broadcast (Android only).
///
/// Invokes the native [MethodChannel] registered in `MainActivity.kt`, which
/// fires an Android broadcast that a separate attacker app can receive.
/// On non-Android platforms (or when the channel is unavailable, e.g. unit
/// tests) the calls are no-ops so the screen falls back to the in-app
/// [OtpBroadcaster] simulation.
class OtpBroadcastBridge {
  const OtpBroadcastBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/otp_broadcast');

  static bool get isAvailable => Platform.isAndroid;

  /// VULN: fire an unprotected broadcast any co-resident app can read.
  /// Returns the native status string, or null if unavailable.
  static Future<String?> broadcastUnprotected(String otp, String link) =>
      _invoke('broadcastUnprotected', otp, link);

  /// SECURE: fire a broadcast gated by a signature-level permission.
  static Future<String?> broadcastSecure(String otp, String link) =>
      _invoke('broadcastSecure', otp, link);

  static Future<String?> _invoke(String method, String otp, String link) =>
      invokeNativeString(_channel, isAvailable, method, {
        'otp': otp,
        'link': link,
      });
}
