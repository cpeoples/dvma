import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// RSA padding helper: legacy PKCS#1 v1.5 vs OAEP.
///
/// INTENTIONALLY VULNERABLE (CWE-780 / CWE-327). The app RSA-encrypts a payload
/// with PKCS#1 v1.5 padding. v1.5 is malleable and its padding-validity check is
/// the classic Bleichenbacher chosen-ciphertext oracle: an attacker who can
/// submit modified ciphertexts and observe whether padding was well-formed
/// recovers the plaintext without the private key. OAEP's randomized,
/// integrity-checked padding removes both the malleability and the oracle.
///
/// Both paths use one real 2048-bit RSA keypair generated at construction, so
/// the round-trips and the tamper behavior below are genuine, not simulated.
class RsaPaddingCrypto {
  RsaPaddingCrypto._(this._public, this._private);

  final RSAPublicKey _public;
  final RSAPrivateKey _private;

  static const String samplePayload = 'grant:transfer;amount=100;to=self';

  /// Builds an instance with a freshly generated 2048-bit RSA keypair.
  factory RsaPaddingCrypto.generate() {
    final params = RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 64);
    final rnd = FortunaRandom()..seed(KeyParameter(_seedBytes()));
    final gen = RSAKeyGenerator()..init(ParametersWithRandom(params, rnd));
    final pair = gen.generateKeyPair();
    return RsaPaddingCrypto._(
      pair.publicKey as RSAPublicKey,
      pair.privateKey as RSAPrivateKey,
    );
  }

  static Uint8List _seedBytes() {
    final r = Random.secure();
    return Uint8List.fromList(List.generate(32, (_) => r.nextInt(256)));
  }

  Uint8List _encrypt(AsymmetricBlockCipher cipher, String plaintext) {
    cipher.init(true, PublicKeyParameter<RSAPublicKey>(_public));
    return cipher.process(Uint8List.fromList(utf8.encode(plaintext)));
  }

  String _decrypt(AsymmetricBlockCipher cipher, Uint8List ct) {
    cipher.init(false, PrivateKeyParameter<RSAPrivateKey>(_private));
    return utf8.decode(cipher.process(ct), allowMalformed: true);
  }

  /// Vulnerable path: encrypt with PKCS#1 v1.5. Returns the ciphertext (hex),
  /// the correct round-trip, and the result of decrypting a tampered
  /// ciphertext - the observable difference in behavior IS the padding oracle.
  ({String hex, String roundTrip, String tamperedBehavior}) pkcs1v15() {
    final ct = _encrypt(PKCS1Encoding(RSAEngine()), samplePayload);
    final roundTrip = _decrypt(
      PKCS1Encoding(RSAEngine()),
      ct,
    ).replaceAll(RegExp(r'[^\x20-\x7e]'), '');
    final tampered = Uint8List.fromList(ct)..[ct.length - 1] ^= 0x01;
    String behavior;
    try {
      _decrypt(PKCS1Encoding(RSAEngine()), tampered);
      behavior =
          'decrypt returned data (padding treated as valid) - oracle signal';
    } on ArgumentError catch (e) {
      behavior =
          'padding rejected: $e (a distinguishable padding-error oracle)';
    } catch (e) {
      behavior = 'padding error: ${e.runtimeType} (a distinguishable oracle)';
    }
    return (hex: _hex(ct), roundTrip: roundTrip, tamperedBehavior: behavior);
  }

  /// Secure path: encrypt with OAEP (SHA-256). Same payload, but the tampered
  /// ciphertext fails the integrity-checked padding uniformly, closing the
  /// oracle.
  ({String hex, String roundTrip, String tamperedBehavior}) oaep() {
    final cipher = OAEPEncoding.withSHA256(RSAEngine());
    cipher.init(true, PublicKeyParameter<RSAPublicKey>(_public));
    final ct = cipher.process(Uint8List.fromList(utf8.encode(samplePayload)));

    final dec = OAEPEncoding.withSHA256(RSAEngine())
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(_private));
    final roundTrip = utf8.decode(dec.process(ct));

    final tampered = Uint8List.fromList(ct)..[ct.length - 1] ^= 0x01;
    String behavior;
    try {
      OAEPEncoding.withSHA256(RSAEngine())
        ..init(false, PrivateKeyParameter<RSAPrivateKey>(_private))
        ..process(tampered);
      behavior = 'decrypt returned data (unexpected)';
    } catch (_) {
      behavior = 'OAEP integrity check FAILED - rejected (no padding oracle)';
    }
    return (hex: _hex(ct), roundTrip: roundTrip, tamperedBehavior: behavior);
  }

  static String _hex(Uint8List b) {
    final head = b.length > 24 ? b.sublist(0, 24) : b;
    final s = head.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
    return b.length > 24 ? '$s… (${b.length} bytes)' : s;
  }
}
