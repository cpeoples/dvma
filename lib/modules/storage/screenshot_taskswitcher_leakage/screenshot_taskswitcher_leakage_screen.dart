import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Screenshot / Task-Switcher Leakage.
///
/// Sensitive screen rendered into the app-switcher snapshot with no
/// FLAG_SECURE.
class ScreenshotTaskswitcherLeakageScreen extends StatefulWidget {
  const ScreenshotTaskswitcherLeakageScreen({super.key});

  static const String vulnId = 'screenshot_taskswitcher_leakage';

  @override
  State<ScreenshotTaskswitcherLeakageScreen> createState() =>
      _ScreenshotTaskswitcherLeakageScreenState();
}

class _ScreenshotTaskswitcherLeakageScreenState
    extends State<ScreenshotTaskswitcherLeakageScreen> {
  // No secure-window flag set. On Android/iOS this means the OS captures
  // this screen into the recent-apps snapshot when the app is backgrounded.
  static const bool secureFlagSet = false; // FLAG_SECURE / hidden snapshot

  // Offline-deterministic model of the background/foreground state used when
  // the real native posture probe is unavailable (iOS/desktop/`flutter test`).
  bool _backgrounded = false;
  String? _nativeState;
  bool _running = false;

  Future<void> _run() async {
    if (_running) return;
    setState(() => _running = true);

    final backgrounded = !_backgrounded;

    // On Android, read the real window FLAG_SECURE / recents-screenshot posture
    // of DVMA's own window. When FLAG_SECURE is unset, this secret-bearing
    // window is eligible to be captured into the recents/task-switcher
    // thumbnail (observable via a real recents screenshot / the posture probe).
    final native = await PlatformIpcBridge.flagSecureState();

    if (backgrounded) {
      // real artifact: record only the truthful posture, that this window is
      // not FLAG_SECURE, so the OS is permitted to capture the secret-bearing
      // view into the recents thumbnail. No fabricated pixel contents.
      await DvmaEvidence.record(
        ScreenshotTaskswitcherLeakageScreen.vulnId,
        'screenshot',
        'window is not FLAG_SECURE (snapshot-hidden=$secureFlagSet), so the OS '
            'captures this secret-bearing screen into the recents/task-switcher '
            'thumbnail on background.',
      );
      if (native != null) {
        await DvmaEvidence.record(
          ScreenshotTaskswitcherLeakageScreen.vulnId,
          'screenshot-native',
          'real recents/FLAG_SECURE posture: $native',
        );
      }
    }

    if (!mounted) return;
    setState(() {
      _backgrounded = backgrounded;
      _nativeState = native;
      _running = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ScreenshotTaskswitcherLeakageScreen.vulnId,
      title: 'Screenshot / Task-Switcher Leakage',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'This sensitive screen does not set FLAG_SECURE (Android) / does not '
          'blur its iOS snapshot, so it is eligible to be captured into the '
          'recents (task-switcher) thumbnail when the app is backgrounded - '
          'readable by anyone with the device or via a real recents screenshot. '
          'A researcher can confirm the posture with the real FLAG_SECURE probe '
          'below and by opening the app switcher; setting FLAG_SECURE / '
          'setRecentsScreenshotEnabled(false) would hide the thumbnail. The '
          'offline model below still tracks the background/foreground state when '
          'the native probe is unavailable.',
      children: [
        EvidencePanel(
          label: 'sensitive content on screen',
          value:
              'Balance: \$84,201.55\nCard: 4111 1111 1111 1111\n'
              'OTP: 559-201',
        ),
        EvidencePanel(
          label: 'secure snapshot flag',
          value: 'FLAG_SECURE / snapshot-hidden = $secureFlagSet',
        ),
        DemoActionButton(
          label: _running
              ? 'Working...'
              : (_backgrounded ? 'Return to app' : 'Send app to background'),
          onPressed: _running ? () {} : _run,
        ),
        if (_backgrounded)
          EvidencePanel(
            label: 'task-switcher exposure (offline model)',
            value:
                'FLAG_SECURE unset -> secret-bearing view eligible for the '
                'recents thumbnail while backgrounded.',
          ),
        if (_nativeState != null)
          EvidencePanel(
            label: 'real recents/FLAG_SECURE posture (device-observable)',
            value: _nativeState!,
          ),
      ],
    );
  }
}
