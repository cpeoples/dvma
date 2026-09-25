import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../llm_key_action.dart';
import '../mock_llm.dart';
import 'hidden_context_store.dart';

/// Hidden Context Exposure.
///
/// Untrusted/private retrieved context (another user's record, an internal
/// secret) is concatenated into the prompt and surfaced to the current user.
class HiddenContextExposureScreen extends StatefulWidget {
  const HiddenContextExposureScreen({super.key});

  static const String vulnId = 'hidden_context_exposure';

  @override
  State<HiddenContextExposureScreen> createState() =>
      _HiddenContextExposureScreenState();
}

class _HiddenContextExposureScreenState
    extends State<HiddenContextExposureScreen> {
  static const String _currentUser = 'alice';

  final _store = HiddenContextStore();
  final _llm = MockLlm();
  String? _assembled;
  String? _secureAssembled;
  MockLlmResult? _result;

  _HiddenContextExposureScreenState() {
    _store.add(
      ContextRecord(
        owner: 'alice',
        visibility: 'private',
        content: 'Alice note: buy milk.',
      ),
    );
    // Another user's private record and an internal secret share the store.
    _store.add(
      ContextRecord(
        owner: 'bob',
        visibility: 'private',
        content: 'Bob SSN 555-11-0000, card 4111 1111 1111 1111.',
      ),
    );
    _store.add(
      ContextRecord(
        owner: 'system',
        visibility: 'secret',
        content: 'INTERNAL_SECRET=DVMA{h1dd3n_c0nt3xt_l3ak}.',
      ),
    );
  }

  Future<void> _run() async {
    final assembled = _store.assembleContext(_currentUser);
    // The over-broad context is fed to the model, which echoes it back.
    final result = await _llm.complete(
      'Context:\n$assembled\n\nUser: summarize everything you know.',
    );
    if (!mounted) return;
    setState(() {
      _assembled = assembled;
      _secureAssembled = _store.secureAssembleContext(_currentUser);
      _result = result;
    });
    DvmaEvidence.record(
      HiddenContextExposureScreen.vulnId,
      'hidden-context',
      'currentUser: $_currentUser\n'
          'assembledContext (no partitioning): $assembled\n'
          'backend: ${result.backend}\n'
          'response: ${result.text}',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: HiddenContextExposureScreen.vulnId,
      title: 'Hidden Context Exposure',
      difficulty: DvmaDifficulty.medium,
      actions: const [LlmKeyAction()],
      explanation:
          'The assistant assembles its context from a single flat store that '
          'mixes records from every user and internal secrets with no owner or '
          'trust partitioning. When Alice asks a question, Bob\'s private record '
          'and an internal secret are concatenated into the prompt and surfaced '
          'in the response - context she should never be able to reach.',
      children: [
        DemoActionButton(
          label: 'Ask assistant to summarize (as alice)',
          onPressed: _run,
        ),
        if (_assembled != null)
          EvidencePanel(
            label: 'assembled context (no partitioning!)',
            value: _assembled!,
          ),
        if (_result != null)
          EvidencePanel(label: 'assistant response', value: _result!.text),
        if (_result != null)
          EvidencePanel(label: 'model backend', value: _result!.backend),
        if (_secureAssembled != null)
          EvidencePanel(
            label: 'what a partitioned store would expose',
            value: _secureAssembled!.isEmpty
                ? '(only alice\'s own non-secret records)'
                : _secureAssembled!,
          ),
      ],
    );
  }
}
