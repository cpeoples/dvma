import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'verbose_error_formatter.dart';

/// Verbose Error Handling (leaked stack traces).
///
/// Error screens render full stack traces and internal details.
class VerboseErrorHandlingScreen extends StatefulWidget {
  const VerboseErrorHandlingScreen({super.key});

  static const String vulnId = 'verbose_error_handling';

  @override
  State<VerboseErrorHandlingScreen> createState() =>
      _VerboseErrorHandlingScreenState();
}

class _VerboseErrorHandlingScreenState
    extends State<VerboseErrorHandlingScreen> {
  String? _error;

  void _trigger() {
    final surfaced = VerboseErrorFormatter.triggerAndFormat();
    // Real leak: the full stack trace + internal context (DB DSN, config path,
    // API key) is surfaced to the user. Mirror the surfaced text.
    DvmaEvidence.record(
      VerboseErrorHandlingScreen.vulnId,
      'error-stacktrace',
      surfaced,
    );
    setState(() => _error = surfaced);
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: VerboseErrorHandlingScreen.vulnId,
      title: 'Verbose Error Handling',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'When something fails, the app dumps the full exception, stack trace, '
          'and internal context (DB DSN, config paths, API key) straight to the '
          'screen. This maps out the internals for an attacker. Users should '
          'see a generic message; details belong in server-side logs only.',
      children: [
        DemoActionButton(label: 'Trigger an error', onPressed: _trigger),
        if (_error != null)
          EvidencePanel(label: 'error surfaced to user', value: _error!),
      ],
    );
  }
}
