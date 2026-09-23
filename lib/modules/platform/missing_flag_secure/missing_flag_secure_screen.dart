import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Missing FLAG_SECURE (screen recording exposure).
///
/// Sensitive screen allows screenshots/recording (no FLAG_SECURE).
///
/// Sensitive screen allows screenshots/recording (no FLAG_SECURE).
class MissingFlagSecureScreen extends StatefulWidget {
  const MissingFlagSecureScreen({super.key});

  static const String vulnId = 'missing_flag_secure';

  @override
  State<MissingFlagSecureScreen> createState() =>
      _MissingFlagSecureScreenState();
}

class _MissingFlagSecureScreenState extends State<MissingFlagSecureScreen> {
  // VULN: this sensitive screen never sets WindowManager.FLAG_SECURE, so the OS
  // and any screen-recorder capture it. The real fix is native; simulated here.
  static const bool flagSecureSet = false;
  String? _capture;
  String? _nativeState;

  Future<void> _record() async {
    final capture =
        'adb shell screenrecord captured this frame:\n'
        'Seed phrase: correct horse battery staple\n'
        'FLAG_SECURE = $flagSecureSet -> capture ALLOWED';
    // real artifact: the screenshot-allowed window state string is written to
    // the adb-pullable evidence file, proving FLAG_SECURE is absent.
    await DvmaEvidence.record(
      MissingFlagSecureScreen.vulnId,
      'flag-secure-state',
      'window screenshot/recording ALLOWED (FLAG_SECURE=$flagSecureSet); '
          'captured frame contained: Seed phrase: correct horse battery staple',
    );

    // On Android, query the real window FLAG_SECURE / recents-screenshot posture
    // of DVMA's own window (device-observable).
    final native = await PlatformIpcBridge.flagSecureState();
    if (native != null) {
      await DvmaEvidence.record(
        MissingFlagSecureScreen.vulnId,
        'flag-secure-native',
        'real window posture: $native',
      );
    }
    if (!mounted) return;
    setState(() {
      _capture = capture;
      _nativeState = native;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: MissingFlagSecureScreen.vulnId,
      title: 'Missing FLAG_SECURE',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'This secret-bearing screen never sets FLAG_SECURE, so screenshots '
          'and screen recording (adb screenrecord, screen-mirroring malware) '
          'capture it. Sensitive screens must set FLAG_SECURE. This is a '
          'native window flag; the button simulates a recorder capturing the '
          'frame.',
      children: [
        EvidencePanel(
          label: 'sensitive content on screen',
          value: 'Seed phrase: correct horse battery staple',
        ),
        DemoActionButton(label: 'Start screen recording', onPressed: _record),
        if (_capture != null)
          EvidencePanel(label: 'recorder output', value: _capture!),
        if (_nativeState != null)
          EvidencePanel(
            label: 'real window FLAG_SECURE posture (device-observable)',
            value: _nativeState!,
          ),
      ],
    );
  }
}
