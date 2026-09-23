import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/resilience_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// App Virtualization / Cloning Detection Not Implemented (Android).
///
/// The app never detects that it is running inside an app-virtualization /
/// cloning container (a VirtualApp-style host, or a dual-app / work-profile
/// clone). In such a container a co-hosted attacker process shares the app's
/// runtime and can read its memory and files. The missing control is the
/// weakness (MASWE-0052), an Android-only surface, so this module is
/// Android-only.
class VirtualizationDetectionAbsentScreen extends StatefulWidget {
  const VirtualizationDetectionAbsentScreen({super.key});

  static const String vulnId = 'virtualization_detection_absent';

  @override
  State<VirtualizationDetectionAbsentScreen> createState() =>
      _VirtualizationDetectionAbsentScreenState();
}

class _VirtualizationDetectionAbsentScreenState
    extends State<VirtualizationDetectionAbsentScreen> {
  String? _result;

  Future<void> _run() async {
    // Read the real cloning-container indicators (work-profile uid, duplicate /
    // non-standard data paths) via the native probe, then run regardless, the
    // app never gates on the verdict.
    final signals = await ResilienceBridge.virtualizationCheck();
    final available = signals != null;

    if (!mounted) return;
    setState(
      () => _result =
          'virtualization/cloning check gated on: false\n'
          'real container indicators available: $available\n'
          'app runs in whatever container hosts it: true\n\n'
          '${signals ?? "(native probe unavailable on this host)"}',
    );
    DvmaEvidence.record(
      VirtualizationDetectionAbsentScreen.vulnId,
      'virtualization-detection-absent',
      'app made no attempt to gate on an app-virtualization / cloning '
          'container. Real indicators read from the environment:\n'
          '${signals ?? "(unavailable)"}',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: VirtualizationDetectionAbsentScreen.vulnId,
      title: 'Virtualization / Cloning Detection Absent',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The app never detects that it is running inside an '
          'app-virtualization / cloning container (a VirtualApp-style host, or '
          'a dual-app / work-profile clone), where a co-hosted attacker '
          'process shares its runtime and can read its memory and files. It '
          'reads the REAL container indicators below via the native probe, then '
          'runs regardless - the missing control is the weakness.',
      children: [
        DemoActionButton(label: 'Run environment check', onPressed: _run),
        if (_result != null)
          EvidencePanel(label: 'real container indicators', value: _result!),
      ],
    );
  }
}
