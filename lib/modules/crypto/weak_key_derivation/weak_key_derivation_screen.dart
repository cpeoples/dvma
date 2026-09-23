import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'weak_kdf.dart';

/// Weak Key Derivation (no/low PBKDF2 iterations).
///
/// Derives keys from passwords with missing or trivial KDF iteration counts.
class WeakKeyDerivationScreen extends StatefulWidget {
  const WeakKeyDerivationScreen({super.key});

  static const String vulnId = 'weak_key_derivation';

  @override
  State<WeakKeyDerivationScreen> createState() =>
      _WeakKeyDerivationScreenState();
}

class _WeakKeyDerivationScreenState extends State<WeakKeyDerivationScreen> {
  final _pw = TextEditingController(text: 'password123');
  String? _pbkdf2;
  String? _raw;

  void _run() {
    final pbkdf2 = WeakKdf.deriveKeyHex(_pw.text);
    final raw = WeakKdf.rawSha256Key(_pw.text);
    setState(() {
      _pbkdf2 = pbkdf2;
      _raw = raw;
    });

    // Surface the real derived keys + weak KDF parameters to the harness.
    DvmaEvidence.record(
      WeakKeyDerivationScreen.vulnId,
      'weak-kdf',
      '${_pw.text} -> PBKDF2-HMAC-SHA256 key=$pbkdf2 '
          '(iterations=${WeakKdf.iterations}, static shared salt); '
          'raw SHA-256 "key" (no KDF)=$raw. Few iterations + fixed salt make '
          'this crackable near-instantly.',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: WeakKeyDerivationScreen.vulnId,
      title: 'Weak Key Derivation',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The encryption key is derived from the password with PBKDF2 at only '
          '${WeakKdf.iterations} iteration and a fixed, shared salt - orders of '
          'magnitude below OWASP guidance - so hashcat cracks it near-instantly. '
          'A second path skips the KDF entirely and uses raw SHA-256(password).',
      children: [
        TextField(
          controller: _pw,
          decoration: const InputDecoration(labelText: 'Password'),
        ),
        DemoActionButton(label: 'Derive key', onPressed: _run),
        if (_pbkdf2 != null)
          EvidencePanel(
            label: 'PBKDF2 key (iterations=${WeakKdf.iterations}, static salt)',
            value: _pbkdf2!,
          ),
        if (_raw != null)
          EvidencePanel(label: 'raw SHA-256 "key" (no KDF)', value: _raw!),
      ],
    );
  }
}
