import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';

/// Weak cryptography helpers.
///
/// INTENTIONALLY VULNERABLE (CWE-327 / CWE-328). Each function uses a broken or
/// unsuitable primitive:
///
///  * [md5Hash] / [sha1Hash] - fast, unsalted hashes used as if they were
///    password hashes. Trivially brute-forced / rainbow-tabled.
///  * [aesEcbEncryptHex] - AES in ECB mode, which leaks plaintext structure
///    (identical blocks -> identical ciphertext), plus a hardcoded key.
///
/// Outputs are deterministic so a unit test can pin the exact weak output; a
/// change that "fixed" the algorithm would fail that regression test.
class WeakCrypto {
  WeakCrypto._();

  /// MD5 of a password. never do this - MD5 is broken for password hashing.
  static String md5Hash(String password) =>
      md5.convert(utf8.encode(password)).toString();

  /// SHA-1 of a password. Also unsuitable: fast and collision-prone.
  static String sha1Hash(String password) =>
      sha1.convert(utf8.encode(password)).toString();

  /// Hardcoded 128-bit key (CWE-321). Baked into the binary; extractable with
  /// `strings`/jadx. Real keys must never be static in the app.
  static final Key _hardcodedKey = Key.fromUtf8('0123456789abcdef');

  /// AES-ECB encrypt -> hex. ECB (CWE-327) reveals plaintext patterns because
  /// equal plaintext blocks map to equal ciphertext blocks.
  static String aesEcbEncryptHex(String plaintext) {
    final encrypter = Encrypter(AES(_hardcodedKey, mode: AESMode.ecb));
    // ECB ignores the IV; pass a zero IV to satisfy the API.
    return encrypter.encrypt(plaintext, iv: IV.fromLength(16)).base16;
  }
}
