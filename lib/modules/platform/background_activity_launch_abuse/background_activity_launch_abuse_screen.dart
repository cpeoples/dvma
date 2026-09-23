import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'activity_launcher.dart';

/// Background Activity Launch Abuse.
///
/// An untrusted / local caller drives a background component to startActivity()
/// reaching security-sensitive UI with no background-activity-launch restriction
/// (Android CVE-2025-26462 class).
class BackgroundActivityLaunchAbuseScreen extends StatefulWidget {
  const BackgroundActivityLaunchAbuseScreen({super.key});

  static const String vulnId = 'background_activity_launch_abuse';

  @override
  State<BackgroundActivityLaunchAbuseScreen> createState() =>
      _BackgroundActivityLaunchAbuseScreenState();
}

class _BackgroundActivityLaunchAbuseScreenState
    extends State<BackgroundActivityLaunchAbuseScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(LaunchResult r) {
    final b = StringBuffer();
    b.writeln('target activity    : ${r.activity}');
    b.writeln('caller foreground  : ${r.callerForeground}');
    b.writeln('sensitive target   : ${r.sensitive}');
    b.writeln('launched           : ${r.launched}');
    b.writeln('blocked            : ${r.blocked}');
    b.writeln('BAL abuse          : ${r.backgroundLaunchAbuse}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    const caller = ActivityLauncher.backgroundAttacker;
    const activity = ActivityLauncher.fakeConsentDialog;
    // VULN: a background caller reaches the fake consent dialog with no BAL
    // restriction.
    final vuln = ActivityLauncher().launch(caller, activity);
    // SECURE: the background caller has no foreground task and no launch token
    // -> refused.
    final secure = ActivityLauncher().launchSafe(caller, activity);
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // On-device: attempt the real background startActivity via the native
    // handler (records to the native EvidenceStore + DVMA-EVIDENCE logcat).
    final native = await PlatformIpcBridge.backgroundActivityLaunch();
    if (!mounted) return;
    if (native != null && native.isNotEmpty) {
      await DvmaEvidence.record(
        BackgroundActivityLaunchAbuseScreen.vulnId,
        'background-activity-launch',
        native,
      );
      if (!mounted) return;
      setState(() => _nativeResult = native);
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: BackgroundActivityLaunchAbuseScreen.vulnId,
      title: 'Background Activity Launch Abuse',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'An untrusted / local caller drives a BACKGROUND component to '
          'startActivity() and reaches a security-sensitive UI - a phishing '
          'overlay, a task-hijack surface, a consent dialog it can manipulate - '
          'because there is NO background-activity-launch (BAL) restriction '
          '(Android CVE-2025-26462 class). Here a background attacker surfaces '
          'a fake consent dialog over the user. This is an offline, '
          'deterministic simulation. The secure path enforces BAL rules: the '
          'caller must be in the foreground OR present a valid launch token, '
          'refusing the background launch otherwise.',
      children: [
        DemoActionButton(
          label: 'Launch sensitive UI from background',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'background caller reaches sensitive activity',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'foreground / launch-token required (refused)',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'native background startActivity (device artifact)',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
