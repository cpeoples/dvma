import 'dart:convert';

import 'package:crypto/crypto.dart';

/// The result of verifying a token's MAC.
class MacVerifyResult {
  MacVerifyResult({
    required this.accepted,
    required this.payload,
    required this.presentedTag,
    required this.expectedTag,
    required this.reason,
  });

  final bool accepted;
  final String payload;
  final String presentedTag;
  final String expectedTag;
  final String reason;
}

/// Improper MAC verification.
///
/// INTENTIONALLY VULNERABLE (CWE-347 / CWE-208, MASWE-0009): a signed token is
/// `<payload>.<hex-hmac>`. Two failures are modelled:
///
///  1. [verify] compares the presented tag to the expected tag with a plain
///     short-circuiting `==`, which returns as soon as the first differing byte
///     is found - a timing oracle an attacker can use to forge a valid tag byte
///     by byte.
///  2. [verifyTrustingUnsignedPayload] skips MAC verification entirely when the
///     token carries no tag, trusting the payload as authentic - so a forged,
///     unsigned token is accepted.
class MacVerifier {
  MacVerifier({this.secret = 'dvma-shared-hmac-secret'});

  final String secret;

  String expectedTag(String payload) {
    final mac = Hmac(sha256, utf8.encode(secret)).convert(utf8.encode(payload));
    return mac.toString();
  }

  /// Issues a legitimately signed `<payload>.<tag>` token.
  String issue(String payload) => '$payload.${expectedTag(payload)}';

  /// VULN: non-constant-time comparison (`==`) leaks a timing side channel.
  MacVerifyResult verify(String token) {
    final dot = token.lastIndexOf('.');
    final payload = dot < 0 ? token : token.substring(0, dot);
    final presented = dot < 0 ? '' : token.substring(dot + 1);
    final expected = expectedTag(payload);

    // INTENTIONALLY VULNERABLE: `==` returns on the first mismatching byte.
    final ok = presented == expected;
    return MacVerifyResult(
      accepted: ok,
      payload: payload,
      presentedTag: presented,
      expectedTag: expected,
      reason: ok
          ? 'tag matched (non-constant-time == : timing oracle)'
          : 'tag mismatch',
    );
  }

  /// VULN: when a token arrives without a tag, verification is skipped and the
  /// payload is trusted - so an unsigned, forged token is accepted.
  MacVerifyResult verifyTrustingUnsignedPayload(String token) {
    if (!token.contains('.')) {
      return MacVerifyResult(
        accepted: true,
        payload: token,
        presentedTag: '',
        expectedTag: expectedTag(token),
        reason: 'no tag present - verification skipped, payload trusted',
      );
    }
    return verify(token);
  }

  /// A secure verifier uses a constant-time compare and always requires a MAC.
  bool secureVerify(String token) {
    final dot = token.lastIndexOf('.');
    if (dot < 0) return false;
    final payload = token.substring(0, dot);
    final presented = utf8.encode(token.substring(dot + 1));
    final expected = utf8.encode(expectedTag(payload));
    if (presented.length != expected.length) return false;
    var diff = 0;
    for (var i = 0; i < expected.length; i++) {
      diff |= presented[i] ^ expected[i];
    }
    return diff == 0;
  }
}
