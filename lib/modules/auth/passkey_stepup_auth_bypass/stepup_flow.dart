/// Step-up authentication flow guarding a sensitive action.
///
/// INTENTIONALLY VULNERABLE (CWE-287 / CWE-863): the "step-up verified" flag is
/// set from the mere *existence* of a registered passkey for the account,
/// rather than from a freshly-completed assertion bound to the step-up
/// challenge. So any logged-in session on a passkey-enrolled account clears the
/// step-up gate without the user actually re-authenticating. Mirrors the
/// New-API AI gateway CVE-2026-32879 class.
///
/// The secure contrast requires a fresh assertion whose challenge matches the
/// step-up challenge that was just issued.
class StepUpFlow {
  StepUpFlow._();

  /// VULN: step-up is considered satisfied if the account merely *has* a
  /// passkey registered - no assertion required.
  static StepUpResult attemptSensitiveAction({
    required bool hasRegisteredPasskey,
    required bool freshAssertionCompleted,
  }) {
    // Bug: presence of a credential is treated as proof of authentication.
    final verified = hasRegisteredPasskey;
    return StepUpResult(verified: verified, actionAllowed: verified);
  }

  /// SECURE: require a fresh assertion whose signed challenge equals the
  /// step-up challenge issued for this action.
  static StepUpResult secureAttemptSensitiveAction({
    required bool hasRegisteredPasskey,
    required bool freshAssertionCompleted,
    required String issuedChallenge,
    required String assertedChallenge,
  }) {
    final verified =
        freshAssertionCompleted &&
        issuedChallenge.isNotEmpty &&
        issuedChallenge == assertedChallenge;
    return StepUpResult(verified: verified, actionAllowed: verified);
  }
}

class StepUpResult {
  StepUpResult({required this.verified, required this.actionAllowed});

  final bool verified;
  final bool actionAllowed;
}
