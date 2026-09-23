import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// The result of checking a payload against an RSA signature.
class SigVerifyResult {
  SigVerifyResult({
    required this.accepted,
    required this.payload,
    required this.tampered,
    required this.reason,
  });

  final bool accepted;
  final String payload;

  /// True when the payload no longer matches what was signed.
  final bool tampered;
  final String reason;
}

/// Improper signature verification.
///
/// INTENTIONALLY VULNERABLE (CWE-347, MASWE-0011): an update/config blob ships
/// with an RSA-SHA256 signature. Real RSA verification runs on a real key pair
/// (pointycastle), but the app's [acceptUpdate] path checks only that a
/// signature is *present and well-formed*, it never binds the signature to the
/// current payload, so a tampered payload with the original (now-stale)
/// signature is accepted. [secureVerify] shows the correct binding.
///
/// The verification is real crypto on real keys, so tampering is genuinely
/// detected by [secureVerify] and genuinely missed by [acceptUpdate].
class SignatureVerifier {
  SignatureVerifier._(this._public, this._private);

  final RSAPublicKey _public;
  final RSAPrivateKey _private;

  /// Builds a verifier with a freshly generated 2048-bit RSA key pair.
  factory SignatureVerifier.generate() {
    final params = RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 64);
    final rnd = FortunaRandom()..seed(KeyParameter(_seedBytes()));
    final gen = RSAKeyGenerator()..init(ParametersWithRandom(params, rnd));
    final pair = gen.generateKeyPair();
    return SignatureVerifier._(
      pair.publicKey as RSAPublicKey,
      pair.privateKey as RSAPrivateKey,
    );
  }

  static Uint8List _seedBytes() {
    final r = Random.secure();
    return Uint8List.fromList(List.generate(32, (_) => r.nextInt(256)));
  }

  /// Signs [payload] with the private key (what the update server does).
  Uint8List sign(String payload) {
    final signer = RSASigner(SHA256Digest(), '0609608648016503040201')
      ..init(true, PrivateKeyParameter<RSAPrivateKey>(_private));
    final sig = signer.generateSignature(
      Uint8List.fromList(utf8.encode(payload)),
    );
    return sig.bytes;
  }

  bool _realVerify(String payload, Uint8List signature) {
    final verifier = RSASigner(SHA256Digest(), '0609608648016503040201')
      ..init(false, PublicKeyParameter<RSAPublicKey>(_public));
    try {
      return verifier.verifySignature(
        Uint8List.fromList(utf8.encode(payload)),
        RSASignature(signature),
      );
    } on ArgumentError {
      return false;
    }
  }

  /// VULN: accepts the update if a signature is merely present and non-empty,
  /// without verifying it binds to [payload]. A tampered payload carrying the
  /// original signature sails through.
  SigVerifyResult acceptUpdate(
    String payload,
    Uint8List signature,
    String signedPayload,
  ) {
    final present = signature.isNotEmpty;
    final tampered = payload != signedPayload;
    return SigVerifyResult(
      accepted: present,
      payload: payload,
      tampered: tampered,
      reason: present
          ? 'signature present (${signature.length} bytes) - accepted without '
                'binding to payload'
          : 'no signature',
    );
  }

  /// A secure app verifies the signature against the exact payload.
  SigVerifyResult secureVerify(
    String payload,
    Uint8List signature,
    String signedPayload,
  ) {
    final ok = _realVerify(payload, signature);
    return SigVerifyResult(
      accepted: ok,
      payload: payload,
      tampered: payload != signedPayload,
      reason: ok
          ? 'signature verified against payload'
          : 'signature does not match payload',
    );
  }
}
