import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'native_channel.dart';

/// Bridge to DVMA's native `dvma/notification` channel.
///
/// iOS counterpart to the Android `PlatformIpc.postSensitiveNotification`: on
/// iOS this schedules a real local `UNNotificationRequest` whose title/body
/// carry the sensitive OTP + balance and reads the delivered content back from
/// `UNUserNotificationCenter`, so push_notification_leakage /
/// notification_action_authorization_bypass produce a genuine iOS notification
/// (visible on the lock screen) rather than a Dart string. Returns null on
/// non-iOS platforms so the caller keeps its existing Android / offline path.
class NotificationBridge {
  const NotificationBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/notification');

  static bool get isAvailable => Platform.isIOS;

  /// Schedules the sensitive local notification and returns the native report
  /// (authorization state + the delivered title/body it read back).
  static Future<String?> postSensitiveNotification() =>
      invokeNativeString(_channel, isAvailable, 'postSensitiveNotification');
}
