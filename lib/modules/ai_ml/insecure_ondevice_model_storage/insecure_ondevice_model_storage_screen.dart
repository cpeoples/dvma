import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'on_device_model_store.dart';

/// Insecure On-Device Model Storage.
///
/// On-device model file is unsigned/unencrypted and swappable.
class InsecureOndeviceModelStorageScreen extends StatefulWidget {
  const InsecureOndeviceModelStorageScreen({super.key});

  static const String vulnId = 'insecure_ondevice_model_storage';

  @override
  State<InsecureOndeviceModelStorageScreen> createState() =>
      _InsecureOndeviceModelStorageScreenState();
}

class _InsecureOndeviceModelStorageScreenState
    extends State<InsecureOndeviceModelStorageScreen> {
  final _store = OnDeviceModelStore();
  String? _path;
  String? _loaded;

  Future<void> _run() async {
    final file = await _store.saveModel('MODEL_WEIGHTS_v1(legit)');
    // Attacker overwrites the unprotected file with a poisoned model.
    await _store.attackerSwap('MODEL_WEIGHTS_v1(POISONED backdoor)');
    final loaded = await _store.loadModel();
    if (!mounted) return;
    setState(() {
      _path = file.path;
      _loaded = loaded;
    });
    DvmaEvidence.record(
      InsecureOndeviceModelStorageScreen.vulnId,
      'model-bytes',
      'path: ${file.path}\n'
          'verifiesSignature: ${OnDeviceModelStore.verifiesSignature}\n'
          'loaded (poisoned, unverified): ${loaded ?? "-"}',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: InsecureOndeviceModelStorageScreen.vulnId,
      title: 'Insecure On-Device Model Storage',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The on-device model is stored unencrypted with no signature, so an '
          'attacker reads it or swaps in a poisoned model and the app loads it '
          'with no integrity check (verifiesSignature = '
          '${OnDeviceModelStore.verifiesSignature}). Below, a legit model is '
          'saved, swapped, and the poisoned bytes load unchallenged.',
      children: [
        DemoActionButton(label: 'Save, swap & load model', onPressed: _run),
        if (_path != null) EvidencePanel(label: 'model path', value: _path!),
        if (_loaded != null)
          EvidencePanel(
            label: 'loaded model (no verification)',
            value: _loaded!,
          ),
      ],
    );
  }
}
