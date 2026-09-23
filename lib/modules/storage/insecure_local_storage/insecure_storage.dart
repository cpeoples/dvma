import 'package:shared_preferences/shared_preferences.dart';

/// Insecure local storage helper.
///
/// INTENTIONALLY VULNERABLE (CWE-312 / CWE-922): writes the auth token and PII
/// straight into SharedPreferences (Android) / NSUserDefaults (iOS) as
/// cleartext. These stores are unencrypted and world-readable on a rooted /
/// jailbroken device or via `adb`/objection. Real apps must use
/// hardware-backed Keychain/Keystore or an encrypted store.
///
/// The logic is factored out of the widget so a unit test can assert that the
/// value is still stored in plaintext (a regression that "fixed" it would
/// break the training scenario and fail CI).
class InsecureStorage {
  InsecureStorage(this._prefs);

  final SharedPreferences _prefs;

  static const String tokenKey = 'auth_token';
  static const String ssnKey = 'user_ssn';
  static const String cardKey = 'credit_card';

  /// Persists sensitive values as cleartext. No encryption, no protection.
  Future<void> saveSensitive({
    required String token,
    required String ssn,
    required String creditCard,
  }) async {
    await _prefs.setString(tokenKey, token);
    await _prefs.setString(ssnKey, ssn);
    await _prefs.setString(cardKey, creditCard);
  }

  /// Returns the raw stored map (as it sits on disk, in cleartext).
  Map<String, String?> dumpRaw() => {
    tokenKey: _prefs.getString(tokenKey),
    ssnKey: _prefs.getString(ssnKey),
    cardKey: _prefs.getString(cardKey),
  };
}
