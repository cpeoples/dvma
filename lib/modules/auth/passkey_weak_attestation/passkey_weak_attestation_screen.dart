import 'package:flutter/material.dart';

import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../passkey_ceremony.dart';
import 'weak_attestation_verifier.dart';

/// Passkey Weak / No Attestation Verification.
///
/// Accepts WebAuthn/passkey registrations with 'none' attestation and never
/// verifies the authenticator attestation statement.
class PasskeyWeakAttestationScreen extends StatefulWidget {
  const PasskeyWeakAttestationScreen({super.key});

  static const String vulnId = 'passkey_weak_attestation';

  @override
  State<PasskeyWeakAttestationScreen> createState() =>
      _PasskeyWeakAttestationScreenState();
}

class _PasskeyWeakAttestationScreenState
    extends State<PasskeyWeakAttestationScreen> {
  String? _result;
  String? _secureResult;
  String? _prefsKey;

  Future<void> _run() async {
    // A rogue/software authenticator returns no attestation statement.
    final att = PasskeyCeremony.register(
      rpId: 'dvma.training',
      userName: 'victim',
      attestationFormat: 'none',
    );
    final accepted = WeakAttestationVerifier.acceptRegistration(att);

    String? prefsKey;
    // VULN: persist the accepted none-attestation registration to real
    // SharedPreferences. The recoverable artifact is a registered credential
    // whose authenticator provenance was never verified.
    if (accepted) {
      prefsKey = await PasskeyEvidenceStore.persist(
        vulnId: PasskeyWeakAttestationScreen.vulnId,
        kind: 'weak-attestation',
        keySuffix: 'registered_${att.credentialId}',
        value:
            'credId=${att.credentialId} rpId=${att.rpId} '
            'fmt=${att.attestationFormat} statement=${att.attestationStatement}',
      );
    }
    if (!mounted) return;

    setState(() {
      _prefsKey = prefsKey;
      _result = accepted
          ? 'ACCEPTED (fmt=${att.attestationFormat}, statement=${att.attestationStatement})'
          : 'rejected';
      _secureResult = WeakAttestationVerifier.secureWouldAccept(att)
          ? 'accepted'
          : 'rejected (no verifiable attestation)';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PasskeyWeakAttestationScreen.vulnId,
      title: 'Passkey Weak Attestation',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'During passkey registration the app never verifies the authenticator '
          'attestation. It accepts fmt:"none" (no statement at all) and never '
          'validates a certificate chain, so a rogue software authenticator is '
          'registered as if it were genuine hardware.'
          ' ${PasskeyCeremony.scopeNote}',
      children: [
        DemoActionButton(
          label: 'Register passkey (none attestation)',
          onPressed: _run,
        ),
        if (_result != null)
          EvidencePanel(label: 'vulnerable app decision', value: _result!),
        if (_prefsKey != null)
          DeviceArtifactPanel(
            storeKey: _prefsKey!,
            describes: 'the registered none-attestation credential',
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'what a secure RP would do',
            value: _secureResult!,
          ),
      ],
    );
  }
}
