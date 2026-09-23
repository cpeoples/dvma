import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'malleable_crypto.dart';

/// Unauthenticated Encryption (malleable ciphertext / bit-flipping).
///
/// AES-CBC with no MAC lets an attacker flip a ciphertext/IV byte to change the
/// decrypted plaintext without the key.
class UnauthenticatedEncryptionMalleableCiphertextScreen
    extends StatefulWidget {
  const UnauthenticatedEncryptionMalleableCiphertextScreen({super.key});

  static const String vulnId =
      'unauthenticated_encryption_malleable_ciphertext';

  @override
  State<UnauthenticatedEncryptionMalleableCiphertextScreen> createState() =>
      _UnauthenticatedEncryptionMalleableCiphertextScreenState();
}

class _UnauthenticatedEncryptionMalleableCiphertextScreenState
    extends State<UnauthenticatedEncryptionMalleableCiphertextScreen> {
  String? _vulnResult;
  String? _secureResult;

  void _runVulnerable() {
    final r = MalleableCrypto.vulnerableRoundTrip();
    setState(
      () => _vulnResult =
          'decrypted before tamper : ${r.original}\n'
          'decrypted after tamper  : ${r.tampered}\n'
          '(the IV was edited with no key; the role escalated to admin)',
    );

    DvmaEvidence.record(
      UnauthenticatedEncryptionMalleableCiphertextScreen.vulnId,
      'bit-flip',
      'AES-CBC, no MAC: original="${r.original}" -> IV-tampered read as '
          '"${r.tampered}". Role escalated to admin without the key.',
    );
  }

  void _runSecure() {
    final r = MalleableCrypto.secureRoundTrip();
    setState(
      () => _secureResult =
          'decrypted (untampered)  : ${r.original}\n'
          'tampered ciphertext     : ${r.tamperedRejected}',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: UnauthenticatedEncryptionMalleableCiphertextScreen.vulnId,
      title: 'Unauthenticated Encryption (bit-flipping)',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The grant token is encrypted with AES-CBC and shipped with NO '
          'integrity tag, so the ciphertext is malleable. Because the first '
          'plaintext block is IV XOR Decrypt(C0), flipping a byte of the IV '
          'flips the same byte of the decrypted block - with no key. Run the '
          'vulnerable path: it encrypts `role=user`, edits only the IV, and the '
          'app then decrypts `role=admin`. The secure path uses authenticated '
          'encryption (AES-GCM); the tag check fails on the edited ciphertext '
          'and decryption is rejected.',
      children: [
        DemoActionButton(
          label: 'Vulnerable: AES-CBC, flip IV -> admin',
          onPressed: _runVulnerable,
        ),
        if (_vulnResult != null)
          EvidencePanel(label: 'CBC (no MAC) result', value: _vulnResult!),
        DemoActionButton(
          label: 'Secure: AES-GCM rejects the tamper',
          onPressed: _runSecure,
        ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'GCM (authenticated) result',
            value: _secureResult!,
          ),
      ],
    );
  }
}
