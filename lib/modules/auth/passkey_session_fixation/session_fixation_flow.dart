/// Login flow that does (not) rotate the session id after a successful passkey
/// assertion.
///
/// INTENTIONALLY VULNERABLE (CWE-384): the session identifier established
/// before authentication is kept as-is after a successful passkey assertion.
/// An attacker who fixes a victim's pre-auth session id (e.g. via a crafted
/// link) still knows the id after the victim logs in, so the attacker's copy
/// of that id is now an authenticated session (session fixation).
///
/// The secure contrast rotates (regenerates) the session id on successful
/// authentication, invalidating any attacker-known pre-auth id.
class SessionFixationFlow {
  SessionFixationFlow._();

  /// VULN: authenticate but keep the pre-auth session id.
  static SessionResult login({
    required String preAuthSessionId,
    required bool assertionValid,
  }) {
    if (!assertionValid) {
      return SessionResult(
        authenticated: false,
        sessionId: preAuthSessionId,
        rotated: false,
      );
    }
    // Bug: no rotation - the attacker-known id is now authenticated.
    return SessionResult(
      authenticated: true,
      sessionId: preAuthSessionId,
      rotated: false,
    );
  }

  /// SECURE: rotate the session id on successful authentication.
  static SessionResult secureLogin({
    required String preAuthSessionId,
    required bool assertionValid,
  }) {
    if (!assertionValid) {
      return SessionResult(
        authenticated: false,
        sessionId: preAuthSessionId,
        rotated: false,
      );
    }
    final fresh = 'sess-rotated-${preAuthSessionId.hashCode.toUnsigned(32)}';
    return SessionResult(
      authenticated: true,
      sessionId: fresh,
      rotated: fresh != preAuthSessionId,
    );
  }
}

class SessionResult {
  SessionResult({
    required this.authenticated,
    required this.sessionId,
    required this.rotated,
  });

  final bool authenticated;
  final String sessionId;
  final bool rotated;
}
