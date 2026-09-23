import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'notification_access_manager.dart';

/// Notification Listener Authorization Bypass.
///
/// Notification-listener access is effectively granted with no proper user
/// grant (above the lock screen, or via an unverified NotificationListenerService
/// intent filter), so a listener reads notification contents with no
/// authorization (Android CVE-2025-22427 / CVE-2025-26442 class).
class NotificationListenerAuthorizationBypassScreen extends StatefulWidget {
  const NotificationListenerAuthorizationBypassScreen({super.key});

  static const String vulnId = 'notification_listener_authorization_bypass';

  @override
  State<NotificationListenerAuthorizationBypassScreen> createState() =>
      _NotificationListenerAuthorizationBypassScreenState();
}

class _NotificationListenerAuthorizationBypassScreenState
    extends State<NotificationListenerAuthorizationBypassScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(ListenerReadResult r) {
    final b = StringBuffer();
    b.writeln('granted            : ${r.granted}');
    b.writeln('blocked            : ${r.blocked}');
    b.writeln('contents leaked    : ${r.contentsLeaked}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    b.writeln('notifications read : ${r.read.length}');
    for (final n in r.read) {
      b.writeln('  - $n');
    }
    return b.toString().trimRight();
  }

  void _run() {
    // Device is LOCKED, the attacker's listener was never verified/granted.
    const listener = NotificationAccessManager.attackerListener;
    // VULN: access granted with no consent record; listener reads everything.
    final vuln = NotificationAccessManager.seeded(deviceUnlocked: false)
        .bindListener(listener);
    // SECURE: unverified component + no unlocked user grant -> refused.
    final secure = NotificationAccessManager.seeded(deviceUnlocked: false)
        .bindListenerSafe(listener);
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // On Android, report the real declared-but-unguarded listener/a11y state
    // and read back the native evidence.
    _runNative();
  }

  Future<void> _runNative() async {
    final native = await PlatformIpcBridge.accessibilityServiceState();
    if (native == null || native.isEmpty) return;
    await DvmaEvidence.record(
      NotificationListenerAuthorizationBypassScreen.vulnId,
      'listener-state',
      'real declared listener / accessibility state:\n$native',
    );
    if (!mounted) return;
    setState(() => _nativeResult = native);
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: NotificationListenerAuthorizationBypassScreen.vulnId,
      title: 'Notification Listener Authorization Bypass',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'Notification-listener access is effectively granted with NO proper '
          'user grant - recorded above the lock screen, or via an UNVERIFIED '
          'NotificationListenerService intent filter - so a listener reads '
          'notification contents (OTP codes, medical messages) with no '
          'authorization and no user interaction (Android CVE-2025-22427 '
          'above-lock grant / CVE-2025-26442 intent-filter verification class). '
          'This is an offline, deterministic simulation. The secure path '
          'requires a persisted user grant recorded while UNLOCKED and a '
          'verified listener component, refusing the read otherwise.',
      children: [
        DemoActionButton(
          label: 'Bind unverified listener (device locked)',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'listener reads notifications with no grant',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label:
                'verified component + unlocked user grant required (refused)',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real declared listener / accessibility state',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
