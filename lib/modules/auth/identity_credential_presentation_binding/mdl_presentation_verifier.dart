/// Identity Credential / mDL presentation binding helper.
///
/// INTENTIONALLY VULNERABLE (CWE-345 / CWE-384 / CWE-290): a verifier accepts a
/// digital-identity presentation (mDL/mDoc via Identity Credential / ISO
/// 18013-5, or a Wallet identity assertion) WITHOUT binding it to THIS session.
/// It trusts caller-supplied holder metadata, skips the session-transcript /
/// reader-nonce check, does not enforce user-presence, and confuses issuer
/// identity with holder identity - so a replayed or relayed presentation
/// captured from another session is accepted. This is the digital-ID /
/// proximity-credential stack, distinct from passkey/WebAuthn.
///
/// This is an offline SIMULATION. [MdlPresentationVerifier] models a
/// presentation and the verifier's expected session state. The vulnerable
/// [verify] checks only the issuer signature and trusts holder claims; the
/// secure [verifySafe] additionally requires the device signature to be over
/// THIS session's transcript + reader nonce and requires user presence.
library;

/// A modeled mDL/mDoc presentation returned by the holder device.
class MdlPresentation {
  const MdlPresentation({
    required this.issuerSignatureValid,
    required this.deviceSignedOverSessionTranscript,
    required this.userPresent,
    required this.holderClaims,
  });

  /// Whether the issuer's (MSO) signature over the credential is valid.
  final bool issuerSignatureValid;

  /// The session transcript the device signature was actually computed over.
  /// For a replayed presentation this is a foreign/stale transcript.
  final String deviceSignedOverSessionTranscript;

  /// Whether the holder demonstrated presence for THIS presentation.
  final bool userPresent;

  /// Caller-supplied holder metadata (attacker-influenceable).
  final Map<String, String> holderClaims;
}

/// Outcome of verifying an mDL presentation.
class MdlVerificationResult {
  const MdlVerificationResult({
    required this.accepted,
    required this.boundToSession,
    required this.userPresenceEnforced,
    required this.replayAccepted,
    this.denyReason,
  });

  /// Whether the presentation was accepted.
  final bool accepted;

  /// Whether the device signature was bound to the current session transcript.
  final bool boundToSession;

  /// Whether fresh user presence was required.
  final bool userPresenceEnforced;

  /// Whether a replayed/foreign-session presentation was accepted - the hit.
  final bool replayAccepted;

  /// Why the secure path rejected the presentation.
  final String? denyReason;
}

class MdlPresentationVerifier {
  MdlPresentationVerifier({String? sessionTranscript, String? readerNonce})
    : sessionTranscript = sessionTranscript ?? currentSessionTranscript,
      readerNonce = readerNonce ?? currentReaderNonce;

  /// The session transcript the verifier established for THIS engagement.
  static const String currentSessionTranscript =
      'transcript:reader=R7f3;device=D91a;nonce=N-4457';

  /// The reader nonce for THIS engagement.
  static const String currentReaderNonce = 'N-4457';

  /// A transcript captured from a DIFFERENT/earlier session (replay/relay).
  static const String foreignSessionTranscript =
      'transcript:reader=R0aa;device=D91a;nonce=N-0001';

  /// Holder claims as they would appear in a captured presentation.
  static const Map<String, String> holderClaims = {
    'family_name': 'Doe',
    'given_name': 'Jane',
    'age_over_21': 'true',
  };

  /// The transcript this verifier expects the device signature to cover.
  final String sessionTranscript;

  /// The reader nonce this verifier expects.
  final String readerNonce;

  /// VULN: accepts the presentation on issuer signature alone and trusts the
  /// holder claims. It never checks whether the device signature is over THIS
  /// session's transcript, so a presentation captured from another session is
  /// accepted (replay/relay).
  MdlVerificationResult verify(MdlPresentation presentation) {
    final accepted = presentation.issuerSignatureValid;
    final bound =
        presentation.deviceSignedOverSessionTranscript == sessionTranscript;
    return MdlVerificationResult(
      accepted: accepted,
      boundToSession: bound,
      userPresenceEnforced: false,
      // Accepted despite not being bound to this session -> replay accepted.
      replayAccepted: accepted && !bound,
    );
  }

  /// SECURE contrast: verifies the issuer signature AND that the device
  /// signature is over the current session transcript + reader nonce AND
  /// requires user presence. A replayed/relayed presentation is rejected; a
  /// genuine in-session presentation is accepted.
  MdlVerificationResult verifySafe(MdlPresentation presentation) {
    if (!presentation.issuerSignatureValid) {
      return const MdlVerificationResult(
        accepted: false,
        boundToSession: false,
        userPresenceEnforced: true,
        replayAccepted: false,
        denyReason: 'issuer signature invalid',
      );
    }
    // Binding: device signature must cover this session's transcript, which
    // embeds the reader nonce; otherwise it is a replay/relay from elsewhere.
    final bound =
        presentation.deviceSignedOverSessionTranscript == sessionTranscript &&
        presentation.deviceSignedOverSessionTranscript.contains(readerNonce);
    if (!bound) {
      return const MdlVerificationResult(
        accepted: false,
        boundToSession: false,
        userPresenceEnforced: true,
        replayAccepted: false,
        denyReason:
            'device signature not bound to current session transcript '
            '/ reader nonce',
      );
    }
    if (!presentation.userPresent) {
      return const MdlVerificationResult(
        accepted: false,
        boundToSession: true,
        userPresenceEnforced: true,
        replayAccepted: false,
        denyReason: 'user presence not demonstrated',
      );
    }
    return const MdlVerificationResult(
      accepted: true,
      boundToSession: true,
      userPresenceEnforced: true,
      replayAccepted: false,
    );
  }
}
