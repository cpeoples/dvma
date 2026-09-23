import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';

/// Weak key-derivation helper.
///
/// INTENTIONALLY VULNERABLE (CWE-916 / CWE-327): derives an encryption key from
/// a password with a trivially-low PBKDF2 iteration count (and a fixed salt),
/// which a real attacker cracks at billions/sec with hashcat. A related
/// [rawSha256Key] path skips a KDF entirely, the "key" is just SHA-256(pw).
///
/// Deterministic (fixed salt + fixed iterations) so a unit test can assert the
/// iteration count stayed weak.
class WeakKdf {
  WeakKdf._();

  /// Way below the OWASP guidance (hundreds of thousands+). This is the flaw.
  static const int iterations = 1;

  /// Fixed, non-random salt shared by all users (also wrong).
  static final Uint8List salt = Uint8List.fromList(utf8.encode('static_salt'));

  static const int keyLengthBytes = 32;

  /// PBKDF2-HMAC-SHA256 with only [iterations] round(s). Returns hex.
  static String deriveKeyHex(String password) {
    final derivator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
      ..init(Pbkdf2Parameters(salt, iterations, keyLengthBytes));
    final key = derivator.process(Uint8List.fromList(utf8.encode(password)));
    return key.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  /// No KDF at all: the "key" is a single SHA-256 of the password (unsalted,
  /// one round). Instantly reversible with a wordlist.
  static String rawSha256Key(String password) =>
      sha256.convert(utf8.encode(password)).toString();
}
