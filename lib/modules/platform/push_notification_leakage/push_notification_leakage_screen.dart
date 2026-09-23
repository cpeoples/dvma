import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/notification_bridge.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Push Notification Leakage.
///
/// Sensitive data placed directly in notification payloads / lockscreen.
class PushNotificationLeakageScreen extends StatefulWidget {
  const PushNotificationLeakageScreen({super.key});

  static const String vulnId = 'push_notification_leakage';

  @override
  State<PushNotificationLeakageScreen> createState() =>
      _PushNotificationLeakageScreenState();
}

class _PushNotificationLeakageScreenState
    extends State<PushNotificationLeakageScreen> {
  // VULN: full secret in the notification body, and lockscreen visibility is
  // PUBLIC (should be VISIBILITY_SECRET / redacted for sensitive content).
  static const String lockscreenVisibility = 'PUBLIC';
  String? _notif;
  String? _nativeResult;

  Future<void> _push() async {
    setState(
      () => _notif =
          'title: Your login code\n'
          'body: Your OTP is 559-201 and your balance is \$84,201.55\n'
          'visibility: $lockscreenVisibility (shown on locked screen)',
    );

    // Post a real notification carrying sensitive content: the Android
    // Notification (lockscreen / listener visible), else a real iOS local
    // UNNotification. Read back the native evidence.
    final native =
        await PlatformIpcBridge.postSensitiveNotification() ??
        await NotificationBridge.postSensitiveNotification();
    if (native == null || native.isEmpty) return;
    await DvmaEvidence.record(
      PushNotificationLeakageScreen.vulnId,
      'sensitive-notification',
      'real Notification with sensitive payload posted:\n$native',
    );
    if (!mounted) return;
    setState(() => _nativeResult = native);
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PushNotificationLeakageScreen.vulnId,
      title: 'Push Notification Leakage',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'The app puts the full OTP and account balance directly in the '
          'notification body with lockscreen visibility PUBLIC, so anyone '
          'glancing at the locked device sees the secret. Sensitive '
          'notifications should be redacted (VISIBILITY_SECRET/private).',
      children: [
        DemoActionButton(label: 'Deliver push notification', onPressed: _push),
        if (_notif != null)
          EvidencePanel(label: 'notification on lockscreen', value: _notif!),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real Notification posted (lockscreen / listener visible)',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
