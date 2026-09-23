import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'homegrown_cipher.dart';

/// Custom / Homegrown Crypto.
///
/// A homegrown XOR-based 'encryption' scheme trivially reversible.
class CustomCryptoImplementationScreen extends StatefulWidget {
  const CustomCryptoImplementationScreen({super.key});

  static const String vulnId = 'custom_crypto_implementation';

  @override
  State<CustomCryptoImplementationScreen> createState() =>
      _CustomCryptoImplementationScreenState();
}

class _CustomCryptoImplementationScreenState
    extends State<CustomCryptoImplementationScreen> {
  final _input = TextEditingController(text: 'attack at dawn');
  String? _cipher;
  String? _recovered;

  void _run() {
    final ct = HomegrownCipher.encrypt(_input.text);
    // Anyone can reverse it with no key material beyond the 4-byte constant.
    final recovered = HomegrownCipher.decrypt(ct);
    setState(() {
      _cipher = ct;
      _recovered = recovered;
    });

    // Mirror the homegrown cipher output + trivial recovery to the harness.
    DvmaEvidence.record(
      CustomCryptoImplementationScreen.vulnId,
      'homegrown-cipher',
      '${_input.text} -> base64 XOR ciphertext=$ct '
          '(repeating-key XOR, key="${HomegrownCipher.key}"); '
          'decrypts back to "$recovered" with no real key material.',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: CustomCryptoImplementationScreen.vulnId,
      title: 'Custom / Homegrown Crypto',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'This "encryption" is repeating-key XOR with a 4-byte constant, '
          'base64-wrapped to look opaque. XOR is its own inverse, so the '
          'ciphertext is reversed with no real key and leaks structure to '
          'frequency analysis. Below, the app decrypts its own output '
          'immediately - proof it protects nothing.',
      children: [
        TextField(
          controller: _input,
          decoration: const InputDecoration(labelText: 'Plaintext'),
        ),
        DemoActionButton(
          label: 'Encrypt with homegrown cipher',
          onPressed: _run,
        ),
        EvidencePanel(label: 'key (constant)', value: HomegrownCipher.key),
        if (_cipher != null)
          EvidencePanel(label: 'ciphertext (base64 XOR)', value: _cipher!),
        if (_recovered != null)
          EvidencePanel(
            label: 'trivially recovered plaintext',
            value: _recovered!,
          ),
      ],
    );
  }
}
