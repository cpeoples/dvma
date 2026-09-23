import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'mdl_presentation_verifier.dart';

/// Identity Credential / mDL Presentation Not Bound.
///
/// A verifier accepts a digital-identity presentation (mDL/mDoc, ISO 18013-5)
/// on issuer signature alone without binding the device signature to THIS
/// session, so a presentation captured from another session is replayed and
/// accepted.
class IdentityCredentialPresentationBindingScreen extends StatefulWidget {
  const IdentityCredentialPresentationBindingScreen({super.key});

  static const String vulnId = 'identity_credential_presentation_binding';

  @override
  State<IdentityCredentialPresentationBindingScreen> createState() =>
      _IdentityCredentialPresentationBindingScreenState();
}

class _IdentityCredentialPresentationBindingScreenState
    extends State<IdentityCredentialPresentationBindingScreen> {
  String? _vulnResult;
  String? _secureResult;

  // A replayed presentation: valid issuer signature, but device-signed over a
  // FOREIGN session transcript, and no fresh user presence.
  static const MdlPresentation _replayedPresentation = MdlPresentation(
    issuerSignatureValid: true,
    deviceSignedOverSessionTranscript:
        MdlPresentationVerifier.foreignSessionTranscript,
    userPresent: false,
    holderClaims: MdlPresentationVerifier.holderClaims,
  );

  // A genuine in-session presentation for the secure-path contrast.
  static const MdlPresentation _genuinePresentation = MdlPresentation(
    issuerSignatureValid: true,
    deviceSignedOverSessionTranscript:
        MdlPresentationVerifier.currentSessionTranscript,
    userPresent: true,
    holderClaims: MdlPresentationVerifier.holderClaims,
  );

  String _render(MdlPresentation p, MdlVerificationResult r) {
    final b = StringBuffer();
    b.writeln(
      'expected transcript: '
      '${MdlPresentationVerifier.currentSessionTranscript}',
    );
    b.writeln(
      'reader nonce       : '
      '${MdlPresentationVerifier.currentReaderNonce}',
    );
    b.writeln('--- presentation ---');
    b.writeln('issuer sig valid   : ${p.issuerSignatureValid}');
    b.writeln('device-signed over : ${p.deviceSignedOverSessionTranscript}');
    b.writeln('user present       : ${p.userPresent}');
    b.writeln('holder claims      : ${p.holderClaims}');
    b.writeln('--- outcome ---');
    b.writeln('accepted           : ${r.accepted}');
    b.writeln('bound to session   : ${r.boundToSession}');
    b.writeln('presence enforced  : ${r.userPresenceEnforced}');
    b.writeln('replay accepted    : ${r.replayAccepted}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    final verifier = MdlPresentationVerifier();

    // VULN: replayed presentation accepted on issuer signature alone.
    final vuln = verifier.verify(_replayedPresentation);

    // SECURE: replayed presentation rejected; genuine in-session accepted.
    final secureReplay = verifier.verifySafe(_replayedPresentation);
    final secureGenuine = verifier.verifySafe(_genuinePresentation);

    // real artifact: record the replayed mDL presentation accepted on issuer
    // signature alone (device-signed over a foreign session transcript).
    await DvmaEvidence.record(
      IdentityCredentialPresentationBindingScreen.vulnId,
      'mdl-replay',
      'replayed mDL accepted=${vuln.accepted} boundToSession=${vuln.boundToSession} '
          'replayAccepted=${vuln.replayAccepted} '
          'deviceSignedOver=${_replayedPresentation.deviceSignedOverSessionTranscript} '
          'expectedTranscript=${MdlPresentationVerifier.currentSessionTranscript} '
          'holderClaims=${_replayedPresentation.holderClaims}',
    );
    if (!mounted) return;
    setState(() {
      _vulnResult = _render(_replayedPresentation, vuln);
      _secureResult =
          '${_render(_replayedPresentation, secureReplay)}\n'
          '--- genuine in-session ---\n'
          '${_render(_genuinePresentation, secureGenuine)}';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: IdentityCredentialPresentationBindingScreen.vulnId,
      title: 'Identity Credential / mDL Presentation Not Bound',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A verifier accepts a digital-identity presentation (mDL/mDoc via '
          'Identity Credential / ISO 18013-5) WITHOUT binding it to THIS '
          'session: it checks only the issuer signature and trusts holder '
          'claims, skipping the session-transcript / reader-nonce check and '
          'user-presence. So a presentation captured from another session is '
          'replayed and accepted. This is the digital-ID / proximity-credential '
          'stack, distinct from passkey/WebAuthn. The secure path additionally '
          'requires the device signature to be over the current session '
          'transcript + reader nonce and requires fresh user presence, so the '
          'replay is rejected while a genuine in-session presentation is '
          'accepted.',
      children: [
        DemoActionButton(
          label: 'Verify replayed mDL presentation',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'issuer-sig only: replayed presentation accepted',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'session-bound + presence: replay rejected',
            value: _secureResult!,
          ),
      ],
    );
  }
}
