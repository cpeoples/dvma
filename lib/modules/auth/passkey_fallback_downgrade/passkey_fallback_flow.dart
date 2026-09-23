/// Login flow that offers passkey auth but silently downgrades to a weak
/// fallback.
///
/// INTENTIONALLY VULNERABLE (CWE-757 / CWE-287): when a passkey assertion is
/// unavailable or "fails", the flow automatically falls back to a weak
/// password/OTP path and treats success there as equivalent. Worse, an
/// attacker can *force* the fallback simply by signalling that passkeys are
/// unavailable, defeating the phishing-resistance passkeys are meant to give.
///
/// A secure flow would not silently downgrade for a passkey-enrolled account,
/// and any fallback would be an explicit, risk-scored, step-up decision.
class PasskeyFallbackFlow {
  PasskeyFallbackFlow._();

  /// The fallback "password" the demo account happens to have (weak on purpose).
  static const String fallbackPassword = 'password1';

  /// Attempts login. If [passkeyAvailable] is false (attacker-forced), the flow
  /// downgrades to the password path and accepts the weak password.
  static LoginResult login({
    required bool passkeyAvailable,
    required bool passkeyAssertionValid,
    String? fallbackAttempt,
  }) {
    if (passkeyAvailable && passkeyAssertionValid) {
      return LoginResult(success: true, method: 'passkey');
    }
    // VULN: silent downgrade to the weak fallback with no step-up / risk check.
    final ok = fallbackAttempt == fallbackPassword;
    return LoginResult(
      success: ok,
      method: 'password-fallback',
      downgraded: true,
    );
  }
}

/// Outcome of a [PasskeyFallbackFlow.login] attempt.
class LoginResult {
  LoginResult({
    required this.success,
    required this.method,
    this.downgraded = false,
  });

  final bool success;
  final String method;
  final bool downgraded;
}
