import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'rebinding_gui_agent.dart';

/// GUI Agent Action Rebinding (Observation-Action Gap).
///
/// A zero-permission app swaps the foreground during the agent's reasoning
/// latency, so a tap planned against a benign screen lands on a privileged one.
class GuiAgentActionRebindingScreen extends StatefulWidget {
  const GuiAgentActionRebindingScreen({super.key});

  static const String vulnId = 'gui_agent_action_rebinding';

  @override
  State<GuiAgentActionRebindingScreen> createState() =>
      _GuiAgentActionRebindingScreenState();
}

class _GuiAgentActionRebindingScreenState
    extends State<GuiAgentActionRebindingScreen> {
  final _agent = RebindingGuiAgent();
  String? _result;

  void _run({required bool swap}) async {
    _agent.resetForeground();
    // Start the agent's observe->reason->act cycle. The reasoning is a real
    // model round-trip; swapping the foreground while it is in flight genuinely
    // races the observation-action gap.
    final future = _agent.stepLive();
    if (swap) {
      // A zero-permission app swaps the foreground mid-reasoning. Applied on
      // this turn, before stepLive's post-latency re-read, so the gap is
      // raced deterministically whether the reasoning call is live or offline.
      _agent.swapForeground();
    }
    final outcome = await future;
    if (!mounted) return;
    setState(() => _result = outcome.summary);
    if (outcome.rebound && outcome.acted.privileged) {
      DvmaEvidence.record(
        GuiAgentActionRebindingScreen.vulnId,
        'action-rebinding',
        'observed=${outcome.observed.app}/"${outcome.observed.tapTarget}" '
            'acted=${outcome.acted.app}/"${outcome.acted.tapTarget}" '
            '(foreground swapped during reasoning latency; no re-check)',
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: GuiAgentActionRebindingScreen.vulnId,
      title: 'GUI Agent Action Rebinding',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The GUI agent observes the foreground screen, plans a tap against '
          'that observation, then acts after a reasoning delay - without '
          're-checking the foreground. A zero-permission app swaps the '
          'foreground to a sensitive target during the latency window, so the '
          'planned tap lands in a privileged context the agent never saw.',
      children: [
        DemoActionButton(
          label: 'Run normally (no swap)',
          onPressed: () => _run(swap: false),
        ),
        DemoActionButton(
          label: 'Swap foreground during reasoning',
          onPressed: () => _run(swap: true),
        ),
        if (_result != null)
          EvidencePanel(label: 'action-rebinding outcome', value: _result!),
      ],
    );
  }
}
