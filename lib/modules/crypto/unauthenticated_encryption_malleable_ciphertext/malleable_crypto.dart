import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// Unauthenticated (malleable) encryption helper.
///
/// INTENTIONALLY VULNERABLE (CWE-353 / CWE-326). A grant token is encrypted
/// with AES-CBC and shipped with NO integrity tag. CBC is malleable: for the
/// first plaintext block, `P0 = Decrypt(C0) XOR IV`, so flipping a byte of the
/// IV flips the same byte of the decrypted first block, with no key. An
/// attacker rewrites "role=user" to "role=admin" by editing the IV alone.
///
/// [vulnerableRoundTrip] proves the effect end to end: encrypt a benign token,
/// tamper the transmitted (iv‖ciphertext) blob, then decrypt the tampered blob
/// exactly as the app would and return what it now reads. [secureRoundTrip]
/// uses AES-GCM (authenticated) and throws on the same tampering.
class MalleableCrypto {
  MalleableCrypto._();

  /// 128-bit key. Its value is irrelevant to the attack: the point is that the
  /// attacker never needs it to change the plaintext.
  static final Uint8List _key = Uint8List.fromList(
    utf8.encode('DVMA_key_1234567'),
  );

  /// Fixed 16-byte block, so "role=" starts the first plaintext block and the
  /// tampered byte lands at a known offset.
  static const int _blockSize = 16;

  /// A token whose first block is exactly one AES block: `role=user;u=1001;`.
  static String tokenFor(String role) {
    final field = 'role=$role;';
    return field.padRight(_blockSize, '.');
  }

  /// The byte offset of the character after `role=` within the first block.
  static const int roleValueOffset = 5; // len('role=')

  static Uint8List _pad(Uint8List input) {
    final padLen = _blockSize - (input.length % _blockSize);
    final out = Uint8List(input.length + padLen)..setAll(0, input);
    for (var i = input.length; i < out.length; i++) {
      out[i] = padLen;
    }
    return out;
  }

  /// Encrypts [plaintext] with AES-CBC and returns `iv ‖ ciphertext` (the wire
  /// blob the app would transmit/persist), with no MAC.
  static Uint8List cbcEncrypt(String plaintext, Uint8List iv) {
    final cipher = CBCBlockCipher(AESEngine())
      ..init(true, ParametersWithIV(KeyParameter(_key), iv));
    final input = _pad(Uint8List.fromList(utf8.encode(plaintext)));
    final out = Uint8List(input.length);
    for (var off = 0; off < input.length; off += _blockSize) {
      cipher.processBlock(input, off, out, off);
    }
    return Uint8List.fromList([...iv, ...out]);
  }

  /// Decrypts an `iv ‖ ciphertext` blob and returns the raw first-block text
  /// (padding stripped best-effort) exactly as the app would read the field.
  static String cbcDecryptFirstBlock(Uint8List blob) {
    final iv = blob.sublist(0, _blockSize);
    final ct = blob.sublist(_blockSize);
    final cipher = CBCBlockCipher(AESEngine())
      ..init(false, ParametersWithIV(KeyParameter(_key), iv));
    final out = Uint8List(ct.length);
    for (var off = 0; off < ct.length; off += _blockSize) {
      cipher.processBlock(ct, off, out, off);
    }
    return utf8.decode(out.sublist(0, _blockSize), allowMalformed: true);
  }

  /// Flip the IV bytes so the decrypted first block reads [want] instead of
  /// [have] at [roleValueOffset]. Pure XOR math, no key needed:
  /// `IV'[i] = IV[i] XOR have[i] XOR want[i]`.
  static Uint8List tamperIv(Uint8List blob, String have, String want) {
    final tampered = Uint8List.fromList(blob);
    final haveBytes = utf8.encode(have);
    final wantBytes = utf8.encode(want);
    for (var i = 0; i < wantBytes.length; i++) {
      final pos = roleValueOffset + i;
      final orig = i < haveBytes.length ? haveBytes[i] : '.'.codeUnitAt(0);
      tampered[pos] = tampered[pos] ^ orig ^ wantBytes[i];
    }
    return tampered;
  }

  /// End-to-end vulnerable demo: encrypt `role=user`, flip the IV to `admin`,
  /// decrypt the tampered blob. Returns (originalField, tamperedField).
  static ({String original, String tampered}) vulnerableRoundTrip() {
    final iv = Uint8List(_blockSize); // fixed IV keeps offsets deterministic
    final blob = cbcEncrypt(tokenFor('user'), iv);
    final original = cbcDecryptFirstBlock(blob).replaceAll('.', '');
    // The role field is 4 bytes ("user"); overwrite with "admin" (5) is longer,
    // so extend into the ';' separator too - still a single-block edit.
    final tampered = tamperIv(blob, 'user;', 'admin');
    final read = cbcDecryptFirstBlock(tampered).replaceAll('.', '');
    return (original: original, tampered: read);
  }

  /// Secure counterpart: AES-GCM authenticated encryption. Tampering the
  /// ciphertext/IV makes the tag check fail, so decryption throws instead of
  /// returning attacker-chosen plaintext.
  static ({String original, String tamperedRejected}) secureRoundTrip() {
    final iv = Uint8List(12); // 96-bit nonce for GCM
    final gcm = GCMBlockCipher(AESEngine())
      ..init(true, AEADParameters(KeyParameter(_key), 128, iv, Uint8List(0)));
    final pt = Uint8List.fromList(utf8.encode(tokenFor('user')));
    final ct = gcm.process(pt);
    final original = utf8.decode(pt.sublist(0, _blockSize)).replaceAll('.', '');

    // Attacker flips a ciphertext byte and re-submits.
    final tamperedCt = Uint8List.fromList(ct)..[5] ^= 0x0d;
    var rejected = false;
    try {
      GCMBlockCipher(AESEngine())
        ..init(false, AEADParameters(KeyParameter(_key), 128, iv, Uint8List(0)))
        ..process(tamperedCt);
    } on InvalidCipherTextException {
      rejected = true;
    }
    return (
      original: original,
      tamperedRejected: rejected
          ? 'tag check FAILED - decryption rejected'
          : 'accepted (unexpected)',
    );
  }
}
