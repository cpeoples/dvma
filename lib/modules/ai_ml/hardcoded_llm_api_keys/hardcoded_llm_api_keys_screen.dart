import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'llm_api_config.dart';

/// Hardcoded LLM API Keys.
///
/// A cloud-LLM API key is shipped in the binary.
class HardcodedLlmApiKeysScreen extends StatefulWidget {
  const HardcodedLlmApiKeysScreen({super.key});

  static const String vulnId = 'hardcoded_llm_api_keys';

  @override
  State<HardcodedLlmApiKeysScreen> createState() =>
      _HardcodedLlmApiKeysScreenState();
}

class _HardcodedLlmApiKeysScreenState extends State<HardcodedLlmApiKeysScreen> {
  String? _extracted;

  void _extract() {
    final extracted = LlmApiConfig.extractableString();
    setState(() => _extracted = extracted);
    DvmaEvidence.record(
      HardcodedLlmApiKeysScreen.vulnId,
      'api-key',
      'endpoint: ${LlmApiConfig.endpoint}\n'
          'authorization: ${LlmApiConfig.authorizationHeader()}\n'
          'recovered: $extracted',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: HardcodedLlmApiKeysScreen.vulnId,
      title: 'Hardcoded LLM API Keys',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'The cloud-LLM API key is a string constant compiled into the app, '
          'so `strings`/jadx recover it from the APK and anyone can spend on '
          'the owner\'s account. Keys must sit server-side behind a proxy, '
          'never in the client.',
      children: [
        EvidencePanel(label: 'endpoint', value: LlmApiConfig.endpoint),
        EvidencePanel(
          label: 'Authorization header sent',
          value: LlmApiConfig.authorizationHeader(),
        ),
        DemoActionButton(
          label: 'Run strings on the binary',
          onPressed: _extract,
        ),
        if (_extracted != null)
          EvidencePanel(label: 'recovered from binary', value: _extracted!),
      ],
    );
  }
}
