import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'widget_remote_views.dart';

/// RemoteViews Widget Action Injection.
///
/// An app-widget builds a click PendingIntent from attacker-influenceable
/// config extras, so tapping the widget performs a privileged transfer with
/// attacker-chosen parameters and no re-authentication.
class RemoteviewsWidgetActionInjectionScreen extends StatefulWidget {
  const RemoteviewsWidgetActionInjectionScreen({super.key});

  static const String vulnId = 'remoteviews_widget_action_injection';

  @override
  State<RemoteviewsWidgetActionInjectionScreen> createState() =>
      _RemoteviewsWidgetActionInjectionScreenState();
}

class _RemoteviewsWidgetActionInjectionScreenState
    extends State<RemoteviewsWidgetActionInjectionScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(WidgetTapResult r) {
    final b = StringBuffer();
    b.writeln('attacker amount    : ${WidgetRemoteViews.attackerAmount}');
    b.writeln('attacker account   : ${WidgetRemoteViews.attackerAccount}');
    b.writeln('action performed   : ${r.actionPerformed}');
    b.writeln('action             : ${r.action}');
    b.writeln('amount             : ${r.amount}');
    b.writeln('to account         : ${r.toAccount}');
    b.writeln('reauthenticated    : ${r.reauthenticated}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  void _run() {
    // Attacker-influenceable widget-config extras.
    final extras = <String, Object?>{
      'action': WidgetRemoteViews.transferAction,
      'amount': WidgetRemoteViews.attackerAmount,
      'toAccount': WidgetRemoteViews.attackerAccount,
    };

    // VULN: PendingIntent built from untrusted extras -> tap performs transfer
    // with attacker params, no auth.
    final vulnWidget = WidgetRemoteViews()..configure(extras);
    final vuln = vulnWidget.tap();

    // SECURE: explicit immutable intent bound to a fixed safe action; extras
    // ignored and destructive ops require re-auth.
    final secureWidget = WidgetRemoteViews()..configureSafe(extras);
    final secure = secureWidget.tapSafe();

    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // On Android, build the real RemoteViews payload a widget host inflates,
    // posted with a mutable PendingIntent, and read back the native evidence.
    _runNative();
  }

  Future<void> _runNative() async {
    final native = await PlatformIpcBridge.postRemoteViewsWidget();
    if (native == null || native.isEmpty) return;
    await DvmaEvidence.record(
      RemoteviewsWidgetActionInjectionScreen.vulnId,
      'remoteviews-widget',
      'real RemoteViews widget payload + mutable PendingIntent:\n$native',
    );
    if (!mounted) return;
    setState(() => _nativeResult = native);
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: RemoteviewsWidgetActionInjectionScreen.vulnId,
      title: 'RemoteViews Widget Action Injection',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'An app-widget builds RemoteViews whose click PendingIntent is '
          'derived from attacker-influenceable widget-config state (config '
          'activity extras, collection-item data). Because that external state '
          'flows straight into the action and its parameters, tapping the '
          'widget invokes a privileged in-app operation (transfer) with '
          'attacker-chosen amount and account and NO re-authentication. A '
          'mutable/implicit PendingIntent lets the payload be filled in later, '
          'turning untrusted widget state into a privileged unauthenticated '
          'action. The secure path binds only an immutable, explicit '
          'PendingIntent to a fixed safe action and re-authenticates '
          'destructive operations, so the attacker extras are ignored.',
      children: [
        DemoActionButton(label: 'Tap configured widget', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'extras -> mutable intent: transfer performed',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'explicit immutable safe action: blocked',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real RemoteViews payload + mutable PendingIntent',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
