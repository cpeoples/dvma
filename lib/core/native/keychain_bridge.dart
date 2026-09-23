import 'dart:io' show Platform;

import 'package:flutter/services.dart';

import 'native_channel.dart';

/// Bridge to DVMA's native `dvma/keychain` channel (see DvmaKeychainProbe.swift).
///
/// iOS backs the two Keychain modules with real `Security.framework` items:
/// `accessGroupConfusion` stores a synchronizable, non-app-private-scoped secret
/// and reads it back across the group boundary; `stateIntegrityTamper` stores an
/// entitlement blob + a real HMAC-SHA256 tag, rewrites the value via
/// `SecItemUpdate`, and contrasts a trusting read vs. a verifying read. Returns
/// null off-iOS so the caller keeps its deterministic model.
class KeychainBridge {
  const KeychainBridge._();

  static const MethodChannel _channel = MethodChannel('dvma/keychain');

  static bool get isAvailable => Platform.isIOS;

  /// keychain_access_group_authorization_confusion: real cross-group read.
  static Future<String?> accessGroupConfusion() =>
      invokeNativeString(_channel, isAvailable, 'accessGroupConfusion');

  /// keychain_state_integrity_manipulation: real SecItemUpdate tamper + verify.
  static Future<String?> stateIntegrityTamper() =>
      invokeNativeString(_channel, isAvailable, 'stateIntegrityTamper');
}
