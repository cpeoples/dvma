import '../passkey_ceremony.dart';

/// Relying-party (app-side) passkey registration verifier.
///
/// INTENTIONALLY VULNERABLE (CWE-345 / CWE-347): it registers a passkey without
/// verifying the attestation statement. It accepts `attestationFormat: 'none'`
/// and even when a statement is present it never validates the certificate
/// chain against a trusted root (metadata service / FIDO MDS). An attacker can
/// therefore register a software/rogue authenticator that the app treats as if
/// it were a genuine hardware security key.
///
/// A secure RP would require and verify attestation for high-assurance flows.
class WeakAttestationVerifier {
  WeakAttestationVerifier._();

  /// Returns true if the app "accepts" the registration. It always does, even
  /// for 'none' attestation with an empty statement - that is the bug.
  static bool acceptRegistration(PasskeyAttestation att) {
    // VULN: no attestation verification at all. We log the format and accept.
    // (A correct implementation would reject 'none' for sensitive accounts and
    // verify att.attestationStatement's x5c chain against FIDO MDS.)
    return true;
  }

  /// What a *secure* verifier would decide, for contrast in the UI/tests.
  static bool secureWouldAccept(PasskeyAttestation att) {
    if (att.attestationFormat == 'none') return false;
    return att.attestationStatement.containsKey('x5c');
  }
}
