import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'recents_snapshot.dart';

/// Predictive Back / Recents Snapshot Leakage.
///
/// The OS captures a snapshot of a sensitive screen for the recents /
/// predictive-back preview because it is not marked secure.
class PredictiveBackLeakageScreen extends StatefulWidget {
  const PredictiveBackLeakageScreen({super.key});

  static const String vulnId = 'predictive_back_leakage';

  @override
  State<PredictiveBackLeakageScreen> createState() =>
      _PredictiveBackLeakageScreenState();
}

class _PredictiveBackLeakageScreenState
    extends State<PredictiveBackLeakageScreen> {
  static const String _sensitive = 'Recovery key: DVMA{r3c3nts_snapsh0t_l3ak}';

  String? _snapshot;
  String? _secureSnapshot;
  String? _nativeState;

  Future<void> _capture() async {
    // VULN: screen not marked secure -> snapshot captures the secret.
    final snapshot = RecentsSnapshotSimulator.captureSnapshot(_sensitive);
    // What FLAG_SECURE / setRecentsScreenshotEnabled(false) would store.
    final secureSnapshot = RecentsSnapshotSimulator.captureSnapshot(
      _sensitive,
      flagSecure: true,
    );
    // real artifact: the retained recents/predictive-back snapshot (which
    // still contains the secret) is written to the adb-pullable evidence file.
    await DvmaEvidence.record(
      PredictiveBackLeakageScreen.vulnId,
      'recents-snapshot',
      'OS retained recents/predictive-back snapshot with secret: $snapshot',
    );

    // On Android, read the real recents-screenshot / FLAG_SECURE posture of
    // DVMA's own window (device-observable via native probe).
    final native = await PlatformIpcBridge.flagSecureState();
    if (native != null) {
      await DvmaEvidence.record(
        PredictiveBackLeakageScreen.vulnId,
        'recents-native',
        'real recents/predictive-back posture: $native',
      );
    }
    if (!mounted) return;
    setState(() {
      _snapshot = snapshot;
      _secureSnapshot = secureSnapshot;
      _nativeState = native;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PredictiveBackLeakageScreen.vulnId,
      title: 'Predictive Back / Recents Leakage',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'This sensitive screen is not marked secure, so Android 14+ captures '
          'its content into the recents (task-switcher) and predictive-back '
          'snapshot, retaining the secret where others can see it. Setting '
          'FLAG_SECURE / setRecentsScreenshotEnabled(false) would store an '
          'obscured placeholder instead. This button simulates the OS snapshot.',
      children: [
        EvidencePanel(label: 'sensitive content on screen', value: _sensitive),
        DemoActionButton(
          label: 'Simulate app-switch (OS captures snapshot)',
          onPressed: _capture,
        ),
        if (_snapshot != null)
          EvidencePanel(
            label: 'retained recents snapshot (leaks!)',
            value: _snapshot!,
          ),
        if (_secureSnapshot != null)
          EvidencePanel(
            label: 'what FLAG_SECURE would retain',
            value: _secureSnapshot!,
          ),
        if (_nativeState != null)
          EvidencePanel(
            label: 'real recents/predictive-back posture (device-observable)',
            value: _nativeState!,
          ),
      ],
    );
  }
}
