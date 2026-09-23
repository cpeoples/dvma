import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

/// Passkey credential store that caches sensitive credential material in
/// app-private SharedPreferences.
///
/// INTENTIONALLY VULNERABLE (CWE-522 / CWE-312): passkey private keys must live
/// in hardware-backed storage (Android Keystore StrongBox / iOS Secure
/// Enclave) and never be exportable. Here the app caches a base64 "private key"
/// blob plus credential metadata in cleartext SharedPreferences, so anyone with
/// filesystem access (rooted/jailbroken device, adb, objection) can exfiltrate
/// and clone the passkey.
class PasskeyCredentialStore {
  PasskeyCredentialStore(this._prefs);

  final SharedPreferences _prefs;

  static const String _key = 'passkey_credentials';

  /// Persists the credential (including "private key" material) as cleartext.
  Future<void> cacheCredential({
    required String credentialId,
    required String rpId,
    required List<int> privateKeyBytes,
  }) async {
    final blob = jsonEncode({
      'credentialId': credentialId,
      'rpId': rpId,
      // VULN: private key material stored, in cleartext, in app-private prefs.
      'privateKey': base64.encode(privateKeyBytes),
    });
    await _prefs.setString(_key, blob);
  }

  /// Simulates an attacker reading the backing store off-device.
  String? exfiltrate() => _prefs.getString(_key);
}
