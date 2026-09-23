import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'weak_crypto.dart';

/// Weak Cryptographic Algorithms (MD5/SHA1/DES/RC4/ECB).
class WeakAlgorithmsScreen extends StatefulWidget {
  const WeakAlgorithmsScreen({super.key});

  static const String vulnId = 'weak_algorithms';

  @override
  State<WeakAlgorithmsScreen> createState() => _WeakAlgorithmsScreenState();
}

class _WeakAlgorithmsScreenState extends State<WeakAlgorithmsScreen> {
  final _input = TextEditingController(text: 'hunter2');
  String? _md5;
  String? _sha1;
  String? _ecb;

  void _run() {
    final md5 = WeakCrypto.md5Hash(_input.text);
    final sha1 = WeakCrypto.sha1Hash(_input.text);
    final ecb = WeakCrypto.aesEcbEncryptHex(_input.text);
    setState(() {
      _md5 = md5;
      _sha1 = sha1;
      _ecb = ecb;
    });

    // Mirror the real weak outputs to the harness (crypto unchanged).
    DvmaEvidence.record(
      WeakAlgorithmsScreen.vulnId,
      'weak-hash',
      '${_input.text} -> MD5=$md5 (unsalted), SHA1=$sha1 (unsalted)',
    );
    DvmaEvidence.record(
      WeakAlgorithmsScreen.vulnId,
      'weak-cipher',
      '${_input.text} -> AES-ECB hex=$ecb (hardcoded key, ECB leaks structure)',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: WeakAlgorithmsScreen.vulnId,
      title: 'Weak Cryptographic Algorithms',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'Passwords are hashed with fast, unsalted MD5/SHA-1 (rainbow-table '
          'and brute-force friendly), and data is "encrypted" with AES-ECB '
          'using a hardcoded key. ECB leaks plaintext structure.',
      children: [
        TextField(
          controller: _input,
          decoration: const InputDecoration(labelText: 'Password / plaintext'),
        ),
        DemoActionButton(label: 'Hash & encrypt (weak)', onPressed: _run),
        if (_md5 != null) EvidencePanel(label: 'MD5 (unsalted)', value: _md5!),
        if (_sha1 != null)
          EvidencePanel(label: 'SHA-1 (unsalted)', value: _sha1!),
        if (_ecb != null)
          EvidencePanel(label: 'AES-ECB hex (hardcoded key)', value: _ecb!),
      ],
    );
  }
}
