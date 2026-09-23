import 'dart:convert';

/// Homegrown "encryption" helper.
///
/// INTENTIONALLY VULNERABLE (CWE-327): a classic repeating-key XOR "cipher"
/// dressed up with base64 to look encrypted. It is trivially reversible
/// (XOR is its own inverse) and leaks structure via frequency analysis. Never
/// roll your own crypto; use a vetted AEAD.
///
/// Symmetric + deterministic so a unit test can prove decrypt(encrypt(x)) == x
/// with no key management at all, i.e. it is not really protecting anything.
class HomegrownCipher {
  HomegrownCipher._();

  /// The "secret" key, a short repeating string.
  static const String key = 'DVMA';

  /// Repeating-key XOR, then base64 so it looks opaque.
  static String encrypt(String plaintext) {
    final data = utf8.encode(plaintext);
    final keyBytes = utf8.encode(key);
    final out = List<int>.generate(
      data.length,
      (i) => data[i] ^ keyBytes[i % keyBytes.length],
    );
    return base64.encode(out);
  }

  /// Reverse the XOR (same operation) after base64-decoding.
  static String decrypt(String ciphertext) {
    final data = base64.decode(ciphertext);
    final keyBytes = utf8.encode(key);
    final out = List<int>.generate(
      data.length,
      (i) => data[i] ^ keyBytes[i % keyBytes.length],
    );
    return utf8.decode(out);
  }
}
