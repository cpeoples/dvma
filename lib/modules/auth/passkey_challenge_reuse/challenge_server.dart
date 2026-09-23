import '../passkey_ceremony.dart';

/// Relying-party server that issues a static / reused challenge and never binds
/// an assertion to a single ceremony.
///
/// INTENTIONALLY VULNERABLE (CWE-294 / CWE-330 / CWE-287): a WebAuthn challenge
/// must be cryptographically random, single-use, and consumed/invalidated after
/// exactly one verification. This server returns a constant challenge and never
/// tracks whether it was already used, so a recorded assertion (which signs
/// over that challenge) is accepted again and again. This is the challenge
/// reuse / not-bound class from the USENIX 2026 passkey analysis.
///
/// The [SecureChallengeServer] contrast issues a fresh random-ish challenge per
/// ceremony and invalidates it on first use.
class ReusedChallengeServer {
  /// VULN: a fixed challenge handed out to everyone, forever.
  static const String staticChallenge = 'chal-STATIC-0000';

  /// Issue the (always identical) challenge.
  String issueChallenge() => staticChallenge;

  /// VULN: verify without consuming the challenge. Any assertion carrying the
  /// static challenge is accepted, including a replay of a recorded one.
  bool verifyAssertion(
    PasskeyAssertion assertion, {
    required String challenge,
  }) {
    if (!assertion.signatureValid) return false;
    return challenge == staticChallenge;
  }
}

/// Correct server: unique, single-use challenges consumed on first verify.
class SecureChallengeServer {
  int _seq = 0;
  final Set<String> _outstanding = <String>{};

  String issueChallenge() {
    // Unique per ceremony (deterministic seq is fine for the offline demo).
    final c = 'chal-${_seq++}-${DateTime(2026).microsecondsSinceEpoch}';
    _outstanding.add(c);
    return c;
  }

  bool verifyAssertion(
    PasskeyAssertion assertion, {
    required String challenge,
  }) {
    if (!assertion.signatureValid) return false;
    // SECURE: challenge must be outstanding; consume it so a replay fails.
    return _outstanding.remove(challenge);
  }
}
