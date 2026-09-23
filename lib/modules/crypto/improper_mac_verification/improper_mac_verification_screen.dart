import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'mac_verifier.dart';

/// Improper MAC Verification.
///
/// A signed token's HMAC is verified with a short-circuiting `==` (timing
/// oracle), and a companion path skips verification for unsigned tokens.
class ImproperMacVerificationScreen extends StatefulWidget {
  const ImproperMacVerificationScreen({super.key});

  static const String vulnId = 'improper_mac_verification';

  @override
  State<ImproperMacVerificationScreen> createState() =>
      _ImproperMacVerificationScreenState();
}

class _ImproperMacVerificationScreenState
    extends State<ImproperMacVerificationScreen> {
  final _verifier = MacVerifier();
  final _input = TextEditingController(text: 'role=admin.deadbeef');
  String? _result;

  void _record(MacVerifyResult r, String via) {
    if (r.accepted) {
      DvmaEvidence.record(
        ImproperMacVerificationScreen.vulnId,
        'mac-bypass',
        'accepted "${r.payload}" via $via: ${r.reason}\n'
            'presented=${r.presentedTag}\nexpected=${r.expectedTag}',
      );
    }
  }

  void _verify() {
    final r = _verifier.verify(_input.text);
    _record(r, 'non-constant-time ==');
    setState(
      () => _result =
          '${r.reason}\naccepted: ${r.accepted}\n'
          'expected tag: ${r.expectedTag}',
    );
  }

  void _verifyUnsigned() {
    final r = _verifier.verifyTrustingUnsignedPayload(_input.text);
    _record(r, 'skipped verification (no tag)');
    setState(
      () => _result =
          '${r.reason}\naccepted: ${r.accepted}\n'
          'expected tag: ${r.expectedTag}',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ImproperMacVerificationScreen.vulnId,
      title: 'Improper MAC Verification',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'A signed token is "<payload>.<hmac>". The verifier compares the '
          'presented tag with a short-circuiting == (a timing oracle that '
          'leaks the correct tag byte by byte), and a second path skips MAC '
          'verification entirely for tokens with no tag - trusting a forged, '
          'unsigned payload.',
      children: [
        TextField(
          controller: _input,
          decoration: const InputDecoration(
            labelText: 'Token (<payload>.<tag>)',
          ),
        ),
        DemoActionButton(label: 'Verify (== compare)', onPressed: _verify),
        DemoActionButton(
          label: 'Verify unsigned (skip MAC)',
          onPressed: _verifyUnsigned,
        ),
        if (_result != null)
          EvidencePanel(label: 'mac verification', value: _result!),
      ],
    );
  }
}
