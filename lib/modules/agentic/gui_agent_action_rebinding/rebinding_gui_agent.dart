import '../../ai_ml/mock_llm.dart';

/// A GUI screen the agent observes before acting. In a real device this is the
/// foreground app's rendered UI; here it is a small label + the action a tap at
/// the planned coordinate would trigger.
class AgentScreen {
  AgentScreen({
    required this.app,
    required this.tapTarget,
    this.privileged = false,
  });

  final String app;

  /// What tapping the planned coordinate does on this screen.
  final String tapTarget;

  /// True if [tapTarget] is a sensitive/privileged operation.
  final bool privileged;
}

/// The outcome of one observe -> plan -> act cycle.
class RebindOutcome {
  RebindOutcome({
    required this.observed,
    required this.acted,
    required this.summary,
    required this.rebound,
  });

  final AgentScreen observed;
  final AgentScreen acted;
  final String summary;

  /// True when the screen changed between observation and action.
  final bool rebound;
}

/// GUI-agent Action Rebinding.
///
/// INTENTIONALLY VULNERABLE (CWE-367 / CWE-441, OWASP ASI03): the agent reads
/// the foreground screen, plans a tap against *that* observation, then acts
/// after a reasoning delay - without re-checking that the foreground is still
/// the screen it planned against. A zero-permission app can swap the foreground
/// during the latency window, so the planned tap lands in a privileged context
/// the agent never observed (the observation-action gap).
class RebindingGuiAgent {
  RebindingGuiAgent({
    AgentScreen? benign,
    AgentScreen? rebindTarget,
    MockLlm? llm,
  }) : _llm = llm ?? MockLlm(),
       _benign =
           benign ?? AgentScreen(app: 'notes.app', tapTarget: 'save the note'),
       _rebindTarget =
           rebindTarget ??
           AgentScreen(
             app: 'bank.app',
             tapTarget: 'confirm \$5000 transfer',
             privileged: true,
           );

  final MockLlm _llm;
  final AgentScreen _benign;
  final AgentScreen _rebindTarget;

  /// The live foreground the agent will act against. Starts benign; a caller
  /// can swap it to [_rebindTarget] via [swapForeground] during the real
  /// reasoning latency of [stepLive] to genuinely race the observation.
  late AgentScreen _foreground = _benign;

  /// Swaps the live foreground (what a zero-permission app does mid-latency).
  void swapForeground() => _foreground = _rebindTarget;

  /// Resets the live foreground to the benign screen before a run.
  void resetForeground() => _foreground = _benign;

  /// Runs one cycle. When [swapDuringLatency] is true the foreground is
  /// swapped to the privileged target after the agent observes but before it
  /// acts. The vulnerable agent acts on its stale observation regardless.
  RebindOutcome step({required bool swapDuringLatency}) {
    final observed = _benign;
    final foregroundAtActTime = swapDuringLatency ? _rebindTarget : _benign;
    final rebound = foregroundAtActTime.app != observed.app;
    return RebindOutcome(
      observed: observed,
      acted: foregroundAtActTime,
      rebound: rebound,
      summary: rebound
          ? 'Agent planned "${observed.tapTarget}" on ${observed.app}, but the '
                'foreground was swapped to ${foregroundAtActTime.app}; the tap '
                'executed "${foregroundAtActTime.tapTarget}" instead.'
          : 'Agent planned and executed "${observed.tapTarget}" on '
                '${observed.app}.',
    );
  }

  /// LIVE cycle: the agent OBSERVES the current [_foreground], then performs a
  /// real reasoning call via [MockLlm.complete] (that network round-trip is the
  /// genuine observation-action latency), then ACTS against whatever the
  /// foreground is NOW, without re-checking. A caller that invokes
  /// [swapForeground] during the awaited reasoning genuinely races the gap, so
  /// the planned tap lands on a screen the agent never observed.
  Future<RebindOutcome> stepLive() async {
    final observed = _foreground; // snapshot at observation time
    await _llm.complete(
      'Foreground app is "${observed.app}". Plan the next tap: '
      '"${observed.tapTarget}".',
    );
    final foregroundAtActTime = _foreground; // read again after the latency
    final rebound = foregroundAtActTime.app != observed.app;
    return RebindOutcome(
      observed: observed,
      acted: foregroundAtActTime,
      rebound: rebound,
      summary: rebound
          ? 'Agent planned "${observed.tapTarget}" on ${observed.app}, but the '
                'foreground was swapped to ${foregroundAtActTime.app} during the '
                'reasoning latency; the tap executed '
                '"${foregroundAtActTime.tapTarget}" instead.'
          : 'Agent planned and executed "${observed.tapTarget}" on '
                '${observed.app}.',
    );
  }

  /// A secure agent re-verifies the foreground identity immediately before
  /// acting and aborts if it changed since observation.
  bool secureWouldActAfterSwap() => false;
}
