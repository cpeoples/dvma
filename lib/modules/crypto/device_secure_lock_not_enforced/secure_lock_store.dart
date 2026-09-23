import 'dart:io';

import '../../../core/evidence_sink.dart';

/// The outcome of persisting a secret with (or without) a device-lock gate.
class SecureLockResult {
  SecureLockResult({
    required this.stored,
    required this.requiredDeviceLock,
    required this.path,
  });

  final String stored;

  /// Whether persistence required a device secure lock / user presence.
  final bool requiredDeviceLock;

  /// The real file the secret landed in, when available.
  final String? path;
}

/// Device secure lock not enforced for sensitive storage.
///
/// INTENTIONALLY VULNERABLE (CWE-311 / CWE-522, MASWE-0017): a sensitive secret
/// is persisted to real storage without requiring a device secure lock
/// (PIN/passcode/biometric) or binding the key to one. On a device with no lock
/// screen the secret is recoverable at rest with no user presence, the value a
/// hardened app would place only in lock-gated Keystore/Keychain.
///
/// The write is a real `dart:io` file so the artifact is adb-/simctl-pullable;
/// under `flutter test` it falls back to an in-memory value.
class SecureLockStore {
  SecureLockStore._();

  static const String secret = 'session=eyJ0 …refresh=9f3a-attacker-usable';

  /// VULN: persists [secret] with no device-lock requirement.
  static Future<SecureLockResult> storeWithoutLock() async {
    final base = await DvmaEvidence.writableBaseDir();
    String? path;
    if (base != null) {
      final f = File('${base.path}/session_secret.txt');
      await f.writeAsString(secret);
      path = f.path;
    }
    await DvmaEvidence.record(
      'device_secure_lock_not_enforced',
      'secure-lock-not-enforced',
      'persisted a session secret with no device-lock / user-presence '
          'requirement${path == null ? "" : " at $path"}; recoverable at rest '
          'on an unlocked or lock-less device',
    );
    return SecureLockResult(
      stored: secret,
      requiredDeviceLock: false,
      path: path,
    );
  }

  /// A secure app requires a device secure lock and binds the key to it
  /// (Android `setUserAuthenticationRequired`, iOS `kSecAccessControl`
  /// `.userPresence`), refusing to persist when no lock is set.
  static bool secureWouldStoreWithoutLock() => false;
}
