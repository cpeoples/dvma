import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'weak_session_manager.dart';

/// Weak Session Management.
///
/// Sessions never expire and use predictable, incrementing tokens.
class WeakSessionManagementScreen extends StatefulWidget {
  const WeakSessionManagementScreen({super.key});

  static const String vulnId = 'weak_session_management';

  @override
  State<WeakSessionManagementScreen> createState() =>
      _WeakSessionManagementScreenState();
}

class _WeakSessionManagementScreenState
    extends State<WeakSessionManagementScreen> {
  final _mgr = WeakSessionManager();
  final List<String> _issued = [];
  String? _predicted;

  void _issue() {
    final token = _mgr.issueToken();
    final predicted = WeakSessionManager.predictNext(token);
    // Real leak: a predictable, never-expiring session token was issued, so
    // the next user's token is directly guessable. Mirror both.
    DvmaEvidence.record(
      WeakSessionManagementScreen.vulnId,
      'session-token',
      'issued=$token predictNext=$predicted',
    );
    setState(() {
      _issued.add(token);
      _predicted = predicted;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: WeakSessionManagementScreen.vulnId,
      title: 'Weak Session Management',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'Session tokens are a simple incrementing counter, so given one token '
          'an attacker guesses the next users\' tokens directly. Sessions also '
          'never expire, so a captured token is valid forever.',
      children: [
        DemoActionButton(label: 'Issue session token', onPressed: _issue),
        if (_issued.isNotEmpty)
          EvidencePanel(
            label: 'issued tokens (predictable, never expire)',
            value: _issued.join('\n'),
          ),
        if (_predicted != null)
          EvidencePanel(
            label: 'attacker-predicted next token',
            value: _predicted!,
          ),
      ],
    );
  }
}
