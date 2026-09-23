/// PendingIntent Provenance Confusion helper.
///
/// INTENTIONALLY VULNERABLE (CWE-441 / CWE-290): a receiving SDK authenticates
/// a caller by trusting a PendingIntent-style token, deriving the caller's
/// identity from what the TOKEN CLAIMS (its `creatorPackage`) rather than from
/// who actually PRESENTS it. A PendingIntent is a capability that can be
/// forwarded/stored/replayed; an attacker who obtains a token minted by
/// `com.trusted.app` can present it and be authenticated AS `com.trusted.app`
/// (confused-deputy / provenance-confusion). This is the PendingIntent
/// provenance-confusion research class (arXiv 2603.02539).
///
/// This is an offline + deterministic simulation: a [PendingIntentToken] is a
/// plain value carrying a claimed creator, and authentication returns the
/// identity the SDK would attribute the call to. A test can assert the
/// vulnerable authenticator returns the trusted identity for an evil presenter
/// (`spoofed == true`), while the strict authenticator rejects the mismatch.
class PendingIntentAuthenticator {
  PendingIntentAuthenticator._();

  /// VULN: authenticate by trusting the token's claimed [PendingIntentToken.creatorPackage]
  /// and IGNORING [presenterPackage]. A forwarded/replayed token from a trusted
  /// app therefore authenticates whoever presents it as that trusted app.
  static AuthResult authenticate(
    PendingIntentToken token,
    String presenterPackage,
  ) {
    final identity = token.creatorPackage; // derived from the token's claim
    final spoofed = presenterPackage != token.creatorPackage;
    return AuthResult(
      authenticated: true,
      identity: identity,
      spoofed: spoofed,
      reason: spoofed
          ? 'authenticated presenter "$presenterPackage" AS "$identity" '
                '(token claim trusted; presenter ignored)'
          : 'authenticated as "$identity"',
    );
  }

  /// SECURE contrast: verify the PRESENTER matches the token's creator (bind
  /// the capability to a single, non-replayable, mutability-restricted use).
  /// A presenter that is not the creator is rejected.
  static AuthResult authenticateStrict(
    PendingIntentToken token,
    String presenterPackage,
  ) {
    if (presenterPackage != token.creatorPackage) {
      return AuthResult(
        authenticated: false,
        identity: null,
        spoofed: false,
        reason:
            'rejected: presenter "$presenterPackage" != creator '
            '"${token.creatorPackage}" (forwarded/replayed token)',
      );
    }
    // Optionally also require a per-use, non-replayable, immutable token.
    if (token.mutable || token.consumed) {
      return AuthResult(
        authenticated: false,
        identity: null,
        spoofed: false,
        reason: 'rejected: token is mutable or already consumed (replayable)',
      );
    }
    return AuthResult(
      authenticated: true,
      identity: token.creatorPackage,
      spoofed: false,
      reason: 'authenticated as "${token.creatorPackage}" (presenter verified)',
    );
  }
}

/// A PendingIntent-style capability token. It CLAIMS a creator package but,
/// like a real PendingIntent, can be forwarded to and presented by any app.
class PendingIntentToken {
  const PendingIntentToken({
    required this.creatorPackage,
    this.mutable = true,
    this.consumed = false,
  });

  /// The package that minted the token (what the token claims).
  final String creatorPackage;

  /// Whether the token's contents can still be filled in/altered (a mutable
  /// PendingIntent is a classic redirection/replay hazard).
  final bool mutable;

  /// Whether the token has already been used (a single-use token cannot be
  /// replayed).
  final bool consumed;
}

/// Outcome of a simulated PendingIntent authentication.
class AuthResult {
  const AuthResult({
    required this.authenticated,
    required this.identity,
    required this.spoofed,
    required this.reason,
  });

  /// Whether the SDK authenticated the caller.
  final bool authenticated;

  /// The identity the SDK attributed the call to, or null when rejected.
  final String? identity;

  /// Whether the authenticated identity differs from the actual presenter
  /// (i.e. the attacker was authenticated as someone else).
  final bool spoofed;

  /// Human-readable explanation of the decision.
  final String reason;
}
