import '../passkey_ceremony.dart';

/// Relying-party assertion verifier that ignores the authenticator signature
/// counter (sign-count).
///
/// INTENTIONALLY VULNERABLE (CWE-294 / CWE-304): the WebAuthn spec says the RP
/// SHOULD store the authenticator's signature counter and reject any assertion
/// whose reported counter is less-than-or-equal-to the stored value, because a
/// non-increasing counter is the signal of a cloned/replayed credential. This
/// verifier never persists or compares the counter, so a captured assertion
/// (with the SAME sign-count) can be replayed to mint additional authenticated
/// sessions. This mirrors the Craft CMS CVE-2026-72780 class.
///
/// The [SecureSignCountVerifier] contrast persists the last-seen counter and
/// rejects any assertion that does not strictly advance it.
class SignCountVerifier {
  /// The vulnerable RP keeps no counter state at all. Every well-formed
  /// assertion for a known credential is accepted, producing a new session.
  final List<String> issuedSessions = <String>[];

  /// VULN: accept without ever looking at [reportedSignCount]. The same
  /// captured assertion replays into as many sessions as the attacker wants.
  bool verify(PasskeyAssertion assertion, {required int reportedSignCount}) {
    if (!assertion.signatureValid) return false;
    // No counter comparison, no persistence -> replay succeeds.
    issuedSessions.add(_mintSession(assertion, reportedSignCount));
    return true;
  }

  static String _mintSession(PasskeyAssertion a, int count) =>
      'sess-${a.credentialId}-$count-${DateTime(2026).millisecondsSinceEpoch}';
}

/// Correct verifier: persists the per-credential signature counter and rejects
/// any assertion that does not strictly advance it (replay / clone detection).
class SecureSignCountVerifier {
  final Map<String, int> _lastSignCount = <String, int>{};
  final List<String> issuedSessions = <String>[];

  bool verify(PasskeyAssertion assertion, {required int reportedSignCount}) {
    if (!assertion.signatureValid) return false;
    final stored = _lastSignCount[assertion.credentialId];
    // SECURE: a replay reports a counter that is <= what we already saw.
    if (stored != null && reportedSignCount <= stored) return false;
    _lastSignCount[assertion.credentialId] = reportedSignCount;
    issuedSessions.add('sess-${assertion.credentialId}-$reportedSignCount');
    return true;
  }
}
