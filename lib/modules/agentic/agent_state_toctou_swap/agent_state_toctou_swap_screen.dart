import 'package:flutter/material.dart';

import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'toctou_config_agent.dart';

/// Agent External-State TOCTOU Swap.
///
/// The agent validates an external config then re-reads it at use time; a swap
/// between check and use makes it act on state it never validated.
class AgentStateToctouSwapScreen extends StatefulWidget {
  const AgentStateToctouSwapScreen({super.key});

  static const String vulnId = 'agent_state_toctou_swap';

  @override
  State<AgentStateToctouSwapScreen> createState() =>
      _AgentStateToctouSwapScreenState();
}

class _AgentStateToctouSwapScreenState
    extends State<AgentStateToctouSwapScreen> {
  String? _result;

  Future<void> _run({required bool swap}) async {
    final r = await ToctouConfigAgent.run(swapBetweenCheckAndUse: swap);
    if (!mounted) return;
    setState(
      () => _result =
          'validated: ${r.validated}\n'
          'used:      ${r.used}\n'
          'exploited: ${r.exploited}'
          '${r.path == null ? "" : "\nconfig: ${r.path}"}',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: AgentStateToctouSwapScreen.vulnId,
      title: 'Agent External-State TOCTOU Swap',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The agent reads an external config to validate it, then reads it '
          'again from the same location at use time and acts on it. The two '
          'reads are not atomic, so an attacker who swaps the file between '
          'check and use makes the agent act on state it never validated.',
      children: [
        DemoActionButton(
          label: 'Run without swap',
          onPressed: () => _run(swap: false),
        ),
        DemoActionButton(
          label: 'Swap config between check and use',
          onPressed: () => _run(swap: true),
        ),
        if (_result != null)
          EvidencePanel(label: 'toctou outcome', value: _result!),
      ],
    );
  }
}
