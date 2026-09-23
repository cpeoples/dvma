/// Relying-party verifier configured with userVerification = REQUIRED that
/// silently fails to enforce the UV flag.
///
/// INTENTIONALLY VULNERABLE (CWE-287 / CWE-306): when the RP requests
/// userVerification = "required", it must reject any authentication assertion
/// whose authenticator-data UV flag is not set (i.e. only User Presence, no
/// biometric/PIN). This verifier checks only User Presence (UP) and ignores
/// the UV bit, so a presence-only assertion (a tap, no biometric) is accepted
/// as if the user had been verified. Mirrors Spring Security CVE-2026-47841.
///
/// The [SecureUvVerifier] contrast enforces UV when the policy requires it.
class UvVerifier {
  UvVerifier._();

  /// The RP's configured policy for this ceremony.
  static const String policy = 'required';

  /// VULN: only checks User Presence; the UV flag is never enforced even
  /// though [policy] is "required".
  static bool verify({
    required bool signatureValid,
    required bool userPresent,
    required bool userVerified,
  }) {
    if (!signatureValid) return false;
    // Bug: UV requirement ignored; presence alone is enough.
    return userPresent;
  }

  /// SECURE: when policy == required, the UV flag must be set.
  static bool secureVerify({
    required bool signatureValid,
    required bool userPresent,
    required bool userVerified,
  }) {
    if (!signatureValid) return false;
    if (!userPresent) return false;
    if (policy == 'required' && !userVerified) return false;
    return true;
  }
}
