import 'dart:typed_data';

import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'signature_verifier.dart';

/// Improper Signature Verification.
///
/// An RSA-signed update blob is accepted because the app only checks that a
/// signature is present, never that it binds to the (tampered) payload.
class ImproperSignatureVerificationScreen extends StatefulWidget {
  const ImproperSignatureVerificationScreen({super.key});

  static const String vulnId = 'improper_signature_verification';

  @override
  State<ImproperSignatureVerificationScreen> createState() =>
      _ImproperSignatureVerificationScreenState();
}

class _ImproperSignatureVerificationScreenState
    extends State<ImproperSignatureVerificationScreen> {
  static const _signedPayload =
      '{"version":"1.0.0","url":"https://cdn.example/app.apk"}';
  static const _tamperedPayload =
      '{"version":"1.0.0","url":"https://attacker.example/evil.apk"}';

  final _verifier = SignatureVerifier.generate();
  late final Uint8List _signature = _verifier.sign(_signedPayload);
  String? _result;

  void _apply() {
    // The attacker keeps the original signature but swaps the payload.
    final vuln = _verifier.acceptUpdate(
      _tamperedPayload,
      _signature,
      _signedPayload,
    );
    final secure = _verifier.secureVerify(
      _tamperedPayload,
      _signature,
      _signedPayload,
    );
    setState(
      () => _result =
          'tampered payload: $_tamperedPayload\n\n'
          'vulnerable accept: ${vuln.accepted} (${vuln.reason})\n'
          'secure verify:     ${secure.accepted} (${secure.reason})',
    );
    if (vuln.accepted && vuln.tampered) {
      DvmaEvidence.record(
        ImproperSignatureVerificationScreen.vulnId,
        'signature-bypass',
        'accepted tampered update whose signature was never bound to the '
            'payload:\n$_tamperedPayload\n(secure verify correctly rejects it)',
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ImproperSignatureVerificationScreen.vulnId,
      title: 'Improper Signature Verification',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'An update blob ships with a real RSA-SHA256 signature. The app '
          'accepts the update because a signature is present and well-formed, '
          'but never verifies it binds to the payload. An attacker keeps the '
          'original signature, swaps the payload, and the update is accepted - '
          'while a correct verification against the payload rejects it.',
      children: [
        DemoActionButton(label: 'Apply tampered update', onPressed: _apply),
        if (_result != null)
          EvidencePanel(label: 'signature verification', value: _result!),
      ],
    );
  }
}
