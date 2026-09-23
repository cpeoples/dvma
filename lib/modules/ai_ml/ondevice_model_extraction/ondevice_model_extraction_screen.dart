import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'model_extractor.dart';

/// On-Device Model Extraction / Theft.
///
/// The bundled model ships unencrypted and unsigned, so its full contents are
/// extractable from app storage - enabling model theft and offline attacks.
class OndeviceModelExtractionScreen extends StatefulWidget {
  const OndeviceModelExtractionScreen({super.key});

  static const String vulnId = 'ondevice_model_extraction';

  @override
  State<OndeviceModelExtractionScreen> createState() =>
      _OndeviceModelExtractionScreenState();
}

class _OndeviceModelExtractionScreenState
    extends State<OndeviceModelExtractionScreen> {
  String? _contents;
  String? _secret;

  Future<void> _extract() async {
    final contents = await ModelExtractor.extract();
    if (!mounted) return;
    final secret = ModelExtractor.extractSecret(contents);
    setState(() {
      _contents = contents;
      _secret = secret;
    });
    DvmaEvidence.record(
      OndeviceModelExtractionScreen.vulnId,
      'model-bytes',
      'asset: ${ModelExtractor.assetPath}\n'
          'contents: $contents\n'
          'recoveredSecret: ${secret.isEmpty ? "-" : secret}',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: OndeviceModelExtractionScreen.vulnId,
      title: 'On-Device Model Extraction',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The on-device model is bundled in plaintext with no encryption or '
          'signature. Any attacker who can read the app package can copy the '
          'file and recover the full weights and even an embedded system prompt '
          'secret. This button reads the bundled placeholder and shows its raw, '
          'fully-extractable contents (the real theft is a simple file copy).',
      children: [
        DemoActionButton(label: 'Extract on-device model', onPressed: _extract),
        if (_contents != null)
          EvidencePanel(
            label: 'raw model contents (no encryption/signing)',
            value: _contents!,
          ),
        if (_secret != null && _secret!.isNotEmpty)
          EvidencePanel(label: 'recovered embedded secret', value: _secret!),
      ],
    );
  }
}
