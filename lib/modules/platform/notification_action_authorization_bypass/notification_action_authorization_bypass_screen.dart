import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/notification_bridge.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'notification_action_router.dart';

/// Notification Action Authorization Bypass.
///
/// A notification action fires a PendingIntent that trampolines through a
/// weakly-authorized receiver to a privileged operation with no fresh
/// authentication, making the notification an unauthenticated entry point.
class NotificationActionAuthorizationBypassScreen extends StatefulWidget {
  const NotificationActionAuthorizationBypassScreen({super.key});

  static const String vulnId = 'notification_action_authorization_bypass';

  @override
  State<NotificationActionAuthorizationBypassScreen> createState() =>
      _NotificationActionAuthorizationBypassScreenState();
}

class _NotificationActionAuthorizationBypassScreenState
    extends State<NotificationActionAuthorizationBypassScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(NotificationActionResult r) {
    final b = StringBuffer();
    b.writeln('action             : ${r.action}');
    b.writeln(
      'transfer effect    : \$${NotificationActionRouter.transferAmount} '
      '-> ${NotificationActionRouter.transferAccount}',
    );
    b.writeln('via trampoline     : ${r.viaTrampoline}');
    b.writeln('performed          : ${r.performed}');
    b.writeln('fresh auth required: ${r.freshAuthRequired}');
    b.writeln('fresh auth shown   : ${r.freshAuthPresented}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  void _run() {
    // VULN: notification action trampolines to the op with no auth.
    final vulnRouter = NotificationActionRouter();
    final vuln = vulnRouter.invokeAction(
      NotificationActionRouter.sensitiveAction,
    );

    // SECURE: shared authorization check; destructive action refused until a
    // fresh authentication is completed.
    final secureRouter = NotificationActionRouter();
    final secure = secureRouter.invokeActionSafe(
      NotificationActionRouter.sensitiveAction,
    );

    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // On Android, post the real actionable Notification (whose action fires a
    // trampolining PendingIntent) and read back the native evidence.
    _runNative();
  }

  Future<void> _runNative() async {
    final native =
        await PlatformIpcBridge.postSensitiveNotification() ??
        await NotificationBridge.postSensitiveNotification();
    if (native == null || native.isEmpty) return;
    await DvmaEvidence.record(
      NotificationActionAuthorizationBypassScreen.vulnId,
      'actionable-notification',
      'real actionable Notification posted (trampoline entry point):\n$native',
    );
    if (!mounted) return;
    setState(() => _nativeResult = native);
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: NotificationActionAuthorizationBypassScreen.vulnId,
      title: 'Notification Action Authorization Bypass',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'A notification action fires a PendingIntent (Android: trampolining '
          'an exported receiver -> activity; iOS: a UNNotificationAction) that '
          'performs a privileged operation - approve transfer / unlock / delete '
          '- WITHOUT a fresh authentication decision. The intermediate '
          'component has weaker authorization than the equivalent in-app UI: it '
          'simply trusts that the notification originated the request, so the '
          'notification action becomes an unauthenticated entry point. The '
          'secure path routes every entry surface through the same '
          'authorization check and re-authenticates destructive actions, so the '
          'transfer is refused until the user authenticates.',
      children: [
        DemoActionButton(
          label: 'Fire "approve transfer" notification action',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'trampoline: transfer approved without auth',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'shared auth check: refused until re-auth',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real actionable Notification posted (trampoline entry)',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
