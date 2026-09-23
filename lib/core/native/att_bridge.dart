import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'native_channel.dart';

/// Bridge to DVMA's native `dvma/att` channel (see DvmaNativeProbes.swift).
///
/// iOS backs no_tracking_transparency_prompt with the real
/// `ATTrackingManager.trackingAuthorizationStatus` + `ASIdentifierManager`
/// IDFA, proving the app harvests a tracking id while the ATT status is
/// `.notDetermined` (no prompt shown). Returns null off-iOS so the caller keeps
/// its deterministic model.
class AttBridge {
  const AttBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/att');

  static bool get isAvailable => Platform.isIOS;

  static Future<String?> trackingState() =>
      invokeNativeString(_channel, isAvailable, 'trackingState');
}
