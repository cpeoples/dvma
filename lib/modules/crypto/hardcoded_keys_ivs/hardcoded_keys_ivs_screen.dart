import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'hardcoded_crypto.dart';

/// Hardcoded Keys & Static IVs.
///
/// Symmetric key and IV baked into the binary; IV reused across messages.
class HardcodedKeysIvsScreen extends StatefulWidget {
  const HardcodedKeysIvsScreen({super.key});

  static const String vulnId = 'hardcoded_keys_ivs';

  @override
  State<HardcodedKeysIvsScreen> createState() => _HardcodedKeysIvsScreenState();
}

class _HardcodedKeysIvsScreenState extends State<HardcodedKeysIvsScreen> {
  final _input = TextEditingController(text: 'transfer:1000:to:attacker');
  String? _once;
  String? _twice;

  void _run() {
    final once = HardcodedCrypto.encryptHex(_input.text);
    // Encrypt the SAME plaintext again: identical output proves IV reuse.
    final twice = HardcodedCrypto.encryptHex(_input.text);
    setState(() {
      _once = once;
      _twice = twice;
    });

    // Surface the real ciphertext + IV-reuse proof to the harness. Fire-and-
    // forget: the crypto above is unchanged and there's no ordering dependency.
    final identical = once == twice;
    DvmaEvidence.record(
      HardcodedKeysIvsScreen.vulnId,
      'ciphertext',
      '${_input.text} -> $once; key/iv are hardcoded and reused '
          '(key=${HardcodedCrypto.key.base16} iv=${HardcodedCrypto.staticIv.base16}). '
          'Encrypting the same plaintext twice yields $twice '
          '-> identical=$identical (IV reuse in CBC).',
    );
  }

  @override
  Widget build(BuildContext context) {
    final lingo = PlatformLingo.current();
    return VulnDemoScaffold(
      vulnId: HardcodedKeysIvsScreen.vulnId,
      title: 'Hardcoded Keys & Static IVs',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'The AES key and IV are hardcoded in the app and the SAME IV is '
          'reused for every message. Extracting the key with '
          '`strings`/${lingo.binaryInspectTool} '
          'decrypts all traffic forever, and IV reuse in CBC makes identical '
          'plaintexts produce identical ciphertexts (encrypt twice below: the '
          'hex is the same).',
      children: [
        TextField(
          controller: _input,
          decoration: const InputDecoration(labelText: 'Plaintext'),
        ),
        DemoActionButton(label: 'Encrypt (twice)', onPressed: _run),
        EvidencePanel(
          label: 'hardcoded material',
          value:
              'key = ${HardcodedCrypto.key.base16}\n'
              'iv  = ${HardcodedCrypto.staticIv.base16}',
        ),
        if (_once != null) EvidencePanel(label: 'ciphertext #1', value: _once!),
        if (_twice != null)
          EvidencePanel(label: 'ciphertext #2 (identical!)', value: _twice!),
      ],
    );
  }
}
