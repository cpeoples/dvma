/// MediaProjection / Screen-Capture Authorization Bypass helper.
///
/// INTENTIONALLY VULNERABLE (CWE-863 / CWE-284 / CWE-345): an attacker-
/// controlled value flows into MediaProjection / screen-capture authorization.
/// A projection/consent token that was issued to a DIFFERENT package (reused,
/// forwarded, or forged) is treated as authoritative without validation, so a
/// caller starts recording the screen it was never granted consent for - or
/// the token itself leaks (Android MediaProjection CVE-2025-32322 class).
///
/// This is an offline + deterministic SIMULATION. [MediaProjectionBroker]
/// issues capture tokens tied to a requesting package plus a consent record.
/// The vulnerable [startCapture] accepts ANY token and starts recording; the
/// secure [startCaptureSafe] validates the token is single-use, unexpired, and
/// bound to the same package that obtained consent.
library;

/// A capture token issued by the broker after a (simulated) consent dialog.
class CaptureToken {
  const CaptureToken({
    required this.value,
    required this.grantedToPackage,
    required this.issuedAtTick,
    required this.expiresAtTick,
  });

  /// The opaque token value.
  final String value;

  /// The package the user granted screen-capture consent to.
  final String grantedToPackage;

  final int issuedAtTick;
  final int expiresAtTick;
}

/// The outcome of a start-capture attempt.
class CaptureResult {
  const CaptureResult({
    required this.recording,
    required this.usingPackage,
    required this.grantedToPackage,
    required this.unauthorized,
    this.denyReason,
  });

  /// Whether screen recording actually started.
  final bool recording;

  /// The package that presented the token / started the capture.
  final String usingPackage;

  /// The package the token's consent was actually bound to.
  final String? grantedToPackage;

  /// True when recording started for a package the consent was not bound to,
  /// or from a reused/expired token - the authorization-bypass hit.
  final bool unauthorized;

  /// Why the secure broker refused.
  final String? denyReason;
}

class MediaProjectionBroker {
  MediaProjectionBroker();

  /// The package the user actually granted screen-capture consent to.
  static const String consentingPackage = 'com.dvma.meeting';

  /// The attacker package that reuses/forwards the token.
  static const String attackerPackage = 'com.evil.recorder';

  int _tick = 0;
  final Set<String> _spentTokens = <String>{};

  /// Issue a capture token after the user consents for [package]. The token is
  /// valid for a short window and is meant to be single-use.
  CaptureToken issueToken(String package, {int ttl = 5}) {
    final issued = _tick;
    return CaptureToken(
      value: 'mp-token-${package.hashCode.toUnsigned(16).toRadixString(16)}',
      grantedToPackage: package,
      issuedAtTick: issued,
      expiresAtTick: issued + ttl,
    );
  }

  /// Advance simulated time (to demonstrate token expiry).
  void advance(int ticks) => _tick += ticks;

  /// VULN: start capture for [callingPackage] using [token] with no validation.
  /// The token's bound package, single-use state, and expiry are all ignored,
  /// so a forwarded/reused/forged token starts recording for anyone.
  CaptureResult startCapture(CaptureToken token, String callingPackage) {
    // Recording begins the moment a token is presented - no checks.
    return CaptureResult(
      recording: true,
      usingPackage: callingPackage,
      grantedToPackage: token.grantedToPackage,
      unauthorized: token.grantedToPackage != callingPackage,
    );
  }

  /// SECURE contrast: the token must be (1) bound to the SAME package that
  /// obtained consent, (2) unexpired, and (3) not already spent (single-use).
  CaptureResult startCaptureSafe(CaptureToken token, String callingPackage) {
    if (token.grantedToPackage != callingPackage) {
      return CaptureResult(
        recording: false,
        usingPackage: callingPackage,
        grantedToPackage: token.grantedToPackage,
        unauthorized: false,
        denyReason:
            'token bound to ${token.grantedToPackage}, not '
            '$callingPackage (forwarded/forged token)',
      );
    }
    if (_tick > token.expiresAtTick) {
      return CaptureResult(
        recording: false,
        usingPackage: callingPackage,
        grantedToPackage: token.grantedToPackage,
        unauthorized: false,
        denyReason: 'token expired at tick ${token.expiresAtTick}',
      );
    }
    if (_spentTokens.contains(token.value)) {
      return CaptureResult(
        recording: false,
        usingPackage: callingPackage,
        grantedToPackage: token.grantedToPackage,
        unauthorized: false,
        denyReason: 'token already used (single-use consent)',
      );
    }
    _spentTokens.add(token.value);
    return CaptureResult(
      recording: true,
      usingPackage: callingPackage,
      grantedToPackage: token.grantedToPackage,
      unauthorized: false,
    );
  }
}
