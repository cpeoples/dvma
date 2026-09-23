import 'package:encrypt/encrypt.dart';

/// Hardcoded key & static IV helper.
///
/// INTENTIONALLY VULNERABLE (CWE-321 / CWE-329): the AES key and the IV are
/// both baked into the source (extractable with `strings`/jadx/frida) and the
/// SAME IV is reused for every message. IV reuse in CBC leaks equality of
/// plaintext prefixes and enables chosen-plaintext style attacks; a static key
/// means one extraction decrypts everything, forever.
///
/// Deterministic by construction (fixed key + fixed IV), so a unit test can
/// assert the ciphertext is stable across calls, proof the IV is reused.
class HardcodedCrypto {
  HardcodedCrypto._();

  /// 128-bit key hardcoded in the binary.
  static final Key key = Key.fromUtf8('DVMA_hardcoded16');

  /// Static IV reused for every message (should be random & unique per message).
  static final IV staticIv = IV.fromUtf8('DVMA_static_iv16');

  static final Encrypter _encrypter = Encrypter(AES(key, mode: AESMode.cbc));

  /// Encrypts with the hardcoded key and reused static IV -> hex.
  static String encryptHex(String plaintext) =>
      _encrypter.encrypt(plaintext, iv: staticIv).base16;

  /// Decrypts, proving the static key/IV round-trips anything an attacker grabs.
  static String decryptHex(String hex) =>
      _encrypter.decrypt(Encrypted.fromBase16(hex), iv: staticIv);
}
