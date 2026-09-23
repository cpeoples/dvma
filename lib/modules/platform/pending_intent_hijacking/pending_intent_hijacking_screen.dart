import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Pending Intent Hijacking.
///
/// Mutable, implicit PendingIntent can be intercepted/redirected.
class PendingIntentHijackingScreen extends StatefulWidget {
  const PendingIntentHijackingScreen({super.key});

  static const String vulnId = 'pending_intent_hijacking';

  @override
  State<PendingIntentHijackingScreen> createState() =>
      _PendingIntentHijackingScreenState();
}

class _PendingIntentHijackingScreenState
    extends State<PendingIntentHijackingScreen> {
  // The insecure PendingIntent construction (native-level on a real device).
  static const bool mutable = true; // FLAG_MUTABLE (should be IMMUTABLE)
  static const bool implicit = true; // base Intent has no explicit component

  String? _result;
  String? _nativeResult;

  Future<void> _hijack() async {
    // A malicious app that receives the mutable, implicit PendingIntent fills
    // in the blank component/extras and gets it fired with THIS app's identity
    // and permissions.
    setState(
      () => _result =
          'Attacker received PendingIntent (mutable, implicit).\n'
          'Fills base intent -> component=com.evil/.Exfil, adds extras.\n'
          'Fires it: runs with com.dvma identity & permissions.',
    );

    // On Android, post a real mutable+implicit PendingIntent inside a
    // Notification (dumpsys observable) and read back the native evidence.
    final native = await PlatformIpcBridge.postMutablePendingIntent();
    if (native == null || native.isEmpty) return;
    await DvmaEvidence.record(
      PendingIntentHijackingScreen.vulnId,
      'mutable-pending-intent',
      'real mutable+implicit PendingIntent posted:\n$native',
    );
    if (!mounted) return;
    setState(() => _nativeResult = native);
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PendingIntentHijackingScreen.vulnId,
      title: 'Pending Intent Hijacking',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A PendingIntent is created MUTABLE and wraps an IMPLICIT base intent, '
          'so a malicious app it is handed to can fill in the component/extras '
          'and fire it with this app\'s identity and permissions. Should be '
          'FLAG_IMMUTABLE + an explicit intent. Native-level; simulated here.',
      children: [
        EvidencePanel(
          label: 'PendingIntent flags',
          value:
              'mutable = $mutable (FLAG_MUTABLE)\n'
              'implicit base intent = $implicit',
        ),
        DemoActionButton(label: 'Hand to malicious app', onPressed: _hijack),
        if (_result != null)
          EvidencePanel(label: 'hijack result', value: _result!),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real mutable+implicit PendingIntent (dumpsys observable)',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
