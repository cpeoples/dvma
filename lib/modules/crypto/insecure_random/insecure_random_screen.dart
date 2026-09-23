import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'insecure_random.dart';

/// Insecure Randomness (predictable tokens/session IDs).
class InsecureRandomScreen extends StatefulWidget {
  const InsecureRandomScreen({super.key});

  static const String vulnId = 'insecure_random';

  @override
  State<InsecureRandomScreen> createState() => _InsecureRandomScreenState();
}

class _InsecureRandomScreenState extends State<InsecureRandomScreen> {
  List<String> _tokens = [];

  void _run() {
    final tokens = InsecureRandom.predictableTokens(count: 5);
    setState(() {
      _tokens = tokens;
    });

    // A fresh generation reproduces the exact same sequence (fixed seed).
    final replay = InsecureRandom.predictableTokens(count: 5);
    final reproducible = tokens.join(',') == replay.join(',');
    DvmaEvidence.record(
      InsecureRandomScreen.vulnId,
      'insecure-random',
      'seed=${InsecureRandom.knownSeed} tokens=[${tokens.join(', ')}]; '
          'regenerating with the same known seed yields the identical sequence '
          '-> reproducible=$reproducible (non-crypto PRNG, predictable).',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: InsecureRandomScreen.vulnId,
      title: 'Insecure Randomness',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'Session tokens are generated with a non-cryptographic PRNG seeded '
          'with a fixed, known seed. The entire token stream is reproducible '
          'by anyone who knows the seed. Regenerate: the values never change.',
      children: [
        DemoActionButton(label: 'Generate session tokens', onPressed: _run),
        if (_tokens.isNotEmpty)
          EvidencePanel(
            label: 'predictable tokens (seed=${InsecureRandom.knownSeed})',
            value: _tokens.join('\n'),
          ),
      ],
    );
  }
}
