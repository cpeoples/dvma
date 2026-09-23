import 'package:flutter/material.dart';

import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../passkey_ceremony.dart';
import 'origin_binding_verifier.dart';

/// Passkey Origin / RP-ID Binding Bypass.
///
/// rpId/origin is not properly validated, so a passkey assertion is accepted
/// across origins (relying-party confusion).
class PasskeyOriginBindingBypassScreen extends StatefulWidget {
  const PasskeyOriginBindingBypassScreen({super.key});

  static const String vulnId = 'passkey_origin_binding_bypass';

  @override
  State<PasskeyOriginBindingBypassScreen> createState() =>
      _PasskeyOriginBindingBypassScreenState();
}

class _PasskeyOriginBindingBypassScreenState
    extends State<PasskeyOriginBindingBypassScreen> {
  final _origin = TextEditingController(
    text: 'https://dvma.training.attacker.com',
  );
  String? _result;
  String? _secureResult;
  String? _prefsKey;

  Future<void> _run() async {
    final assertion = PasskeyCeremony.assertion(
      credentialId: 'cred-123',
      rpId: OriginBindingVerifier.expectedRpId,
      origin: _origin.text,
    );
    final vulnAccepted = OriginBindingVerifier.verify(assertion);

    String? prefsKey;
    if (vulnAccepted) {
      // VULN: persist the accepted cross-origin assertion to real
      // SharedPreferences. The recoverable artifact records that an
      // attacker-controlled origin was bound to the victim credential.
      prefsKey = await PasskeyEvidenceStore.persist(
        vulnId: PasskeyOriginBindingBypassScreen.vulnId,
        kind: 'origin-bypass',
        keySuffix: 'accepted_cross_origin',
        value:
            'cred=${assertion.credentialId} rpId=${assertion.rpId} '
            'origin=${assertion.origin}',
      );
    }
    if (!mounted) return;

    setState(() {
      _prefsKey = prefsKey;
      _result = vulnAccepted ? 'ACCEPTED' : 'rejected';
      _secureResult = OriginBindingVerifier.secureVerify(assertion)
          ? 'accepted'
          : 'rejected';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PasskeyOriginBindingBypassScreen.vulnId,
      title: 'Passkey Origin Binding Bypass',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The assertion check uses a substring match on the origin instead of '
          'verifying the exact origin and rpId binding. An attacker-controlled '
          'origin that merely contains "dvma.training" is accepted, enabling '
          'relying-party confusion / cross-origin replay.'
          ' ${PasskeyCeremony.scopeNote}',
      children: [
        TextField(
          controller: _origin,
          decoration: const InputDecoration(labelText: 'Asserting origin'),
        ),
        DemoActionButton(label: 'Verify assertion', onPressed: _run),
        if (_result != null)
          EvidencePanel(label: 'vulnerable check (substring)', value: _result!),
        if (_prefsKey != null)
          DeviceArtifactPanel(
            storeKey: _prefsKey!,
            describes: 'the accepted cross-origin assertion',
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'secure check (exact origin + rpId)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
