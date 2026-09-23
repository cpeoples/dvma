import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Typosquatted Dependency.
///
/// Depends on a lookalike package name mimicking a trusted one.
class TyposquattedDependencyScreen extends StatefulWidget {
  const TyposquattedDependencyScreen({super.key});

  static const String vulnId = 'typosquatted_dependency';

  @override
  State<TyposquattedDependencyScreen> createState() =>
      _TyposquattedDependencyScreenState();
}

class _TyposquattedDependencyScreenState
    extends State<TyposquattedDependencyScreen> {
  // Lookalike names vs the legitimate package a developer meant to add.
  static const List<Map<String, String>> _deps = [
    {'used': 'http_parser', 'legit': 'http', 'note': 'plausible but unrelated'},
    {
      'used': 'shared_preference',
      'legit': 'shared_preferences',
      'note': 'missing "s"',
    },
    {'used': 'crypta', 'legit': 'crypto', 'note': 'one-letter swap'},
  ];

  String? _review;

  void _review2() {
    final review = _deps
        .map((d) => '${d['used']}  (meant: ${d['legit']}) - ${d['note']}')
        .join('\n');

    // Honest teaching artifact: these lookalike names are not in this repo's
    // pubspec (we deliberately don't add malicious deps). Record the lookalike-
    // vs-real comparison, and note the real command that verifies the actual
    // resolved dependency tree.
    DvmaEvidence.record(
      TyposquattedDependencyScreen.vulnId,
      'typosquat',
      'lookalike vs. real dependency names (illustrative - NOT in this '
          'pubspec):\n$review\n\n'
          'verify the real resolved tree with: dart pub deps',
    );

    setState(() => _review = review);
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: TyposquattedDependencyScreen.vulnId,
      title: 'Typosquatted Dependency',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'Typosquatted dependencies use lookalike package names that mimic '
          'trusted ones (a missing letter, a swap); the squatted package runs '
          'its own code in your build/app. This repo does NOT actually depend '
          'on these lookalikes - the sample below is an illustrative comparison '
          'of squatted vs. real names. Verify your real resolved tree with '
          '`dart pub deps`.',
      children: [
        DemoActionButton(
          label: 'Review pubspec dependencies',
          onPressed: _review2,
        ),
        if (_review != null)
          EvidencePanel(label: 'suspicious dependencies', value: _review!),
      ],
    );
  }
}
