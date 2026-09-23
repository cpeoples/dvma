import '../passkey_ceremony.dart';

/// Relying-party passkey assertion verifier with a broken origin/rpId check.
///
/// INTENTIONALLY VULNERABLE (CWE-346 / CWE-287): when validating an
/// authentication assertion, it only checks that the origin *contains* the
/// rpId substring instead of verifying the fully-qualified origin and rpId
/// binding. That lets an attacker-controlled origin such as
/// `https://dvma.training.attacker.com` (or `https://notdvma.training`) satisfy
/// the check, enabling relying-party confusion / cross-origin replay.
class OriginBindingVerifier {
  OriginBindingVerifier._();

  static const String expectedRpId = 'dvma.training';
  static const String expectedOrigin = 'https://dvma.training';

  /// The vulnerable check: substring match on the origin.
  static bool verify(PasskeyAssertion assertion) {
    if (!assertion.signatureValid) return false;
    // VULN: substring containment instead of exact origin + rpId binding.
    return assertion.origin.contains(expectedRpId);
  }

  /// A correct check: exact origin match and rpId equality.
  static bool secureVerify(PasskeyAssertion assertion) {
    if (!assertion.signatureValid) return false;
    return assertion.origin == expectedOrigin && assertion.rpId == expectedRpId;
  }
}
