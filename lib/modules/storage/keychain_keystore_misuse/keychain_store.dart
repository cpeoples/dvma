import 'package:flutter/services.dart' show MissingPluginException;
import 'package:shared_preferences/shared_preferences.dart';

/// Keychain/Keystore misuse helper.
///
/// INTENTIONALLY VULNERABLE (CWE-312 / CWE-522): simulates a "secure" secret
/// store that is neither hardware-backed nor protected by a sensible
/// accessibility class. On a real device this maps to storing secrets in the
/// iOS Keychain with `kSecAttrAccessibleAlways` (readable while locked,
/// migrated to new devices via backup) or the Android Keystore without
/// `setUserAuthenticationRequired` / hardware backing.
///
/// real ARTIFACT: instead of only keeping the secret in a Dart `Map`, the
/// "secure" store now writes the secret straight into SharedPreferences -
/// backed by `/data/data/<pkg>/shared_prefs/FlutterSharedPreferences.xml` on
/// Android, which is adb-pullable / objection-readable. That XML is the real
/// keychain-misuse artifact: a "secret" stored with the weakest protection
/// class landing in a plain, unencrypted file. An in-memory fallback keeps the
/// demo deterministic under `flutter test` (where platform channels are
/// unavailable).
class KeychainStore {
  KeychainStore();

  /// In-memory fallback used under test / when platform channels are missing.
  final Map<String, String> _memory = {};

  /// SharedPreferences key prefix so the weak "keychain" items are easy to
  /// spot in the backing XML (`keychain_<accessibility>_<key>`).
  static String prefsKey(String key) => 'keychain_${accessibility}_$key';

  /// The weakest iOS accessibility class: readable even when the device is
  /// locked, and included in unencrypted backups. A secure app would use
  /// `whenUnlockedThisDeviceOnly` (or better, `whenPasscodeSetThisDeviceOnly`).
  static const String accessibility = 'kSecAttrAccessibleAlways';

  /// Whether biometric/user-presence is required before reading. It is not.
  static const bool requiresUserAuthentication = false;

  /// Whether the key material is bound to secure hardware (StrongBox / SE).
  static const bool hardwareBacked = false;

  /// Stores a secret with no protection class worth the name. On device this
  /// writes the value to the SharedPreferences XML in cleartext, tagged with
  /// the weak accessibility class; under test it falls back to memory.
  Future<void> store(String key, String secret) async {
    _memory[key] = secret;
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(prefsKey(key), secret);
    } on MissingPluginException {
      // Platform channel unavailable (e.g. `flutter test`): memory holds it.
    } catch (_) {
      // Any other store failure: the in-memory fallback keeps the demo alive.
    }
  }

  /// Reads a secret. There is no auth gate: anyone with device access (or a
  /// `frida`/`keychain-dumper` hook) gets the cleartext value.
  Future<String?> read(String key) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final value = prefs.getString(prefsKey(key));
      if (value != null) return value;
    } on MissingPluginException {
      // Fall through to the in-memory fallback.
    } catch (_) {
      // Fall through to the in-memory fallback.
    }
    return _memory[key];
  }

  /// Dumps every stored item, as `keychain-dumper` / objection would. Reads
  /// back the real prefs values when available, else the in-memory fallback.
  Future<Map<String, String>> dumpAll() async {
    final out = <String, String>{};
    for (final key in _memory.keys) {
      out[key] = (await read(key)) ?? _memory[key]!;
    }
    return out;
  }
}
