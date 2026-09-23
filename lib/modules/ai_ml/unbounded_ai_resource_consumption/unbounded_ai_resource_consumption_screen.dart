import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../mock_llm.dart';

/// Unbounded AI Resource Consumption.
///
/// No rate limiting on AI calls enables a cost-exhaustion attack.
class UnboundedAiResourceConsumptionScreen extends StatefulWidget {
  const UnboundedAiResourceConsumptionScreen({super.key});

  static const String vulnId = 'unbounded_ai_resource_consumption';

  @override
  State<UnboundedAiResourceConsumptionScreen> createState() =>
      _UnboundedAiResourceConsumptionScreenState();
}

class _UnboundedAiResourceConsumptionScreenState
    extends State<UnboundedAiResourceConsumptionScreen> {
  final _llm = MockLlm();
  int _burst = 1000;
  String? _result;

  void _flood() {
    // VULN: no per-user quota, no throttle. We can invoke the model as many
    // times as we like, each call is billable against the app's API key.
    // This uses the offline MockLlm.run deliberately, the demo is about
    // the unbounded CALL COUNT (denial-of-wallet), so firing thousands of real
    // network calls would be genuinely abusive and rate-limit us instantly. The
    // vulnerability (no throttle) is real; the per-call cost is illustrative.
    for (var i = 0; i < _burst; i++) {
      _llm.run('expensive request #$i');
    }
    final estCost = (_llm.callCount * 0.002).toStringAsFixed(2);
    setState(
      () => _result =
          'total calls made = ${_llm.callCount} (no rate limit)\n'
          'est. cost @ \$0.002/call = \$$estCost',
    );
    DvmaEvidence.record(
      UnboundedAiResourceConsumptionScreen.vulnId,
      'cost',
      'burst: $_burst\n'
          'totalCalls: ${_llm.callCount} (no rate limit)\n'
          'estCost @ \$0.002/call: \$$estCost',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: UnboundedAiResourceConsumptionScreen.vulnId,
      title: 'Unbounded AI Resource Consumption',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'The assistant applies no rate limiting or per-user quota, so an '
          'attacker floods it with requests - each billed against the app\'s '
          'API key - for a cost-exhaustion / denial-of-wallet attack. Fire a '
          'burst and watch the unbounded call count.',
      children: [
        // Isolate the Slider's adjustable semantics inside its own container so
        // it cannot absorb the sibling action button's node on iOS (a Flutter
        // iOS quirk: an adjustable element adjacent to a tappable can merge the
        // tappable's `demo_action_*` identifier out of the tree, which made the
        // XCUITest walk find 0 actions on this screen).
        Semantics(
          container: true,
          explicitChildNodes: true,
          child: Row(
            children: [
              const Text('burst size: '),
              Expanded(
                child: Slider(
                  value: _burst.toDouble(),
                  min: 100,
                  max: 5000,
                  divisions: 49,
                  label: '$_burst',
                  activeColor: DvmaColors.accent,
                  onChanged: (v) => setState(() => _burst = v.round()),
                ),
              ),
            ],
          ),
        ),
        DemoActionButton(label: 'Flood the assistant', onPressed: _flood),
        if (_result != null)
          EvidencePanel(label: 'consumption', value: _result!),
      ],
    );
  }
}
