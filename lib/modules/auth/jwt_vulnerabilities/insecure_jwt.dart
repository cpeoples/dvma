import 'dart:convert';

import 'package:crypto/crypto.dart';

/// Insecure JWT verifier.
///
/// INTENTIONALLY VULNERABLE (CWE-347 / CWE-345): a hand-rolled JWT check that
///
///  * accepts `alg: none` tokens as valid (skips signature verification), and
///  * uses a weak, guessable HMAC secret when a signature IS present.
///
/// Both are classic JWT footguns. Pure Dart + deterministic so a unit test can
/// forge an alg:none admin token and assert it is accepted.
class InsecureJwt {
  InsecureJwt._();

  /// A weak, guessable HMAC secret (top of every wordlist).
  static const String weakSecret = 'secret';

  static String _b64url(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');

  static String _b64urlStr(String s) => _b64url(utf8.encode(s));

  /// Forges a token with `alg:none` and no signature.
  static String forgeNoneToken(Map<String, Object?> claims) {
    final header = _b64urlStr(jsonEncode({'alg': 'none', 'typ': 'JWT'}));
    final payload = _b64urlStr(jsonEncode(claims));
    return '$header.$payload.'; // empty signature
  }

  /// Signs a token with the weak secret (HS256).
  static String signWeak(Map<String, Object?> claims) {
    final header = _b64urlStr(jsonEncode({'alg': 'HS256', 'typ': 'JWT'}));
    final payload = _b64urlStr(jsonEncode(claims));
    final signing = '$header.$payload';
    final sig = Hmac(
      sha256,
      utf8.encode(weakSecret),
    ).convert(utf8.encode(signing)).bytes;
    return '$signing.${_b64url(sig)}';
  }

  /// The vulnerable verify. Returns the decoded claims if "valid".
  ///
  /// Accepts alg:none unconditionally, and only otherwise checks the HMAC with
  /// the weak secret. A secure verifier pins the expected algorithm and rejects
  /// `none`.
  static Map<String, Object?>? verify(String token) {
    final parts = token.split('.');
    if (parts.length != 3) return null;
    final header = jsonDecode(_decodeSegment(parts[0])) as Map<String, Object?>;
    final claims = jsonDecode(_decodeSegment(parts[1])) as Map<String, Object?>;

    final alg = header['alg'];
    // VULN: alg:none is accepted, signature ignored entirely.
    if (alg == 'none') return claims;

    // VULN: verifies with the weak, guessable secret.
    final signing = '${parts[0]}.${parts[1]}';
    final expected = _b64url(
      Hmac(sha256, utf8.encode(weakSecret)).convert(utf8.encode(signing)).bytes,
    );
    if (expected == parts[2]) return claims;
    return null;
  }

  static String _decodeSegment(String seg) =>
      utf8.decode(base64Url.decode(base64Url.normalize(seg)));
}
