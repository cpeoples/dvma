import 'dart:io' show Platform;

import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/notification_bridge.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'lock_screen_reader.dart';

/// Lock-State Confusion Data Exposure.
///
/// Sensitive data is reachable while the device is LOCKED through an alternate
/// (accessibility / VoiceOver / widget) path that never re-checks the keyguard
/// (iOS CVE-2026-20645 / CVE-2026-20661 class).
class LockStateConfusionDataExposureScreen extends StatefulWidget {
  const LockStateConfusionDataExposureScreen({super.key});

  static const String vulnId = 'lock_state_confusion_data_exposure';

  @override
  State<LockStateConfusionDataExposureScreen> createState() =>
      _LockStateConfusionDataExposureScreenState();
}

class _LockStateConfusionDataExposureScreenState
    extends State<LockStateConfusionDataExposureScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeReport;
  bool _running = false;

  String _render(LockReadResult r) {
    final b = StringBuffer();
    b.writeln('access path        : ${r.path.name}');
    b.writeln('device locked      : ${r.locked}');
    b.writeln('leaked while locked: ${r.leakedWhileLocked}');
    b.writeln('displayed          : ${r.displayed}');
    if (r.reason != null) {
      b.writeln('reason             : ${r.reason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    if (_running) return;
    setState(() => _running = true);

    const surface = LockScreenSurface.sample; // locked == true
    const reader = LockScreenReader();
    // real LOGIC: the VoiceOver path returns full protected content while
    // locked (never re-checks the keyguard).
    final vuln = reader.read(surface, path: AccessPath.voiceOver);
    // SECURE: the keyguard is re-checked on the same path -> redacted.
    final secure = reader.readSafe(surface, path: AccessPath.voiceOver);

    // real SINK: drive the protected content onto a genuine locked-surface by
    // posting an actual OS notification whose body carries the sensitive
    // wallet content. On a locked device this renders on the real lock screen /
    // status bar (Android: observable via `adb shell dumpsys notification`;
    // iOS: a real UNNotificationRequest on the lock screen). Off-platform the
    // bridge returns null and the demo falls back to the offline model above.
    final native = Platform.isIOS
        ? await NotificationBridge.postSensitiveNotification()
        : await PlatformIpcBridge.postSensitiveNotification();

    // Mirror the sensitive data exposed while 'locked' to the pullable evidence
    // sink (fire-and-forget; never blocks the demo).
    DvmaEvidence.record(
      LockStateConfusionDataExposureScreen.vulnId,
      'lock-exposure',
      'access path = ${vuln.path.name}; device locked = ${vuln.locked}\n'
          'exposed while locked: ${vuln.displayed}\n'
          'leaked while locked = ${vuln.leakedWhileLocked}\n'
          'real locked-surface notification: '
          '${native ?? "(native surface unavailable on host)"}',
    );

    if (!mounted) return;
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
      _nativeReport = native;
      _running = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: LockStateConfusionDataExposureScreen.vulnId,
      title: 'Lock-State Confusion Data Exposure',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'Sensitive data is reachable while the device is LOCKED through an '
          'alternate path - an accessibility / notification / widget / '
          'VoiceOver surface - that never re-checks the keyguard, so the '
          'lock-screen boundary is bypassed and protected content is exposed on '
          'a locked device (iOS CVE-2026-20645 / CVE-2026-20661 lock-screen '
          'VoiceOver disclosure class). Here the VoiceOver path reads the full '
          'wallet balance while the phone is locked, and the same sensitive '
          'content is driven onto a REAL locked surface by posting an actual OS '
          'notification (observable via `adb shell dumpsys notification` / the '
          'lock screen). The keyguard-confusion decision logic is real; the '
          'in-memory model is retained as the offline fallback when no native '
          'surface is available. The secure path re-checks the lock state on '
          'every path and returns only redacted content while locked.',
      children: [
        DemoActionButton(
          label: _running
              ? 'Reading...'
              : 'Read via VoiceOver on locked device',
          onPressed: _running ? () {} : _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'alternate path skips keyguard (leaks while locked)',
            value: _vulnResult!,
          ),
        if (_nativeReport != null)
          EvidencePanel(
            label: 'real locked-surface notification (dumpsys / lock screen)',
            value: _nativeReport!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'keyguard re-checked on every path (redacted)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
