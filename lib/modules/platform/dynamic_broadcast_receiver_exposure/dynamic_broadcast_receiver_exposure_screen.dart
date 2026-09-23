import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/native/broadcast_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'dynamic_receiver_registry.dart';

/// Dynamic BroadcastReceiver Exposure.
///
/// A runtime-registered receiver without RECEIVER_NOT_EXPORTED / a signature
/// permission is implicitly exported, so a co-resident app forges a broadcast
/// that triggers a sensitive action.
class DynamicBroadcastReceiverExposureScreen extends StatefulWidget {
  const DynamicBroadcastReceiverExposureScreen({super.key});

  static const String vulnId = 'dynamic_broadcast_receiver_exposure';

  @override
  State<DynamicBroadcastReceiverExposureScreen> createState() =>
      _DynamicBroadcastReceiverExposureScreenState();
}

class _DynamicBroadcastReceiverExposureScreenState
    extends State<DynamicBroadcastReceiverExposureScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeApplied;

  String _render(RegisteredReceiver receiver, BroadcastDeliveryResult r) {
    final b = StringBuffer();
    b.writeln('action             : ${r.action}');
    b.writeln('receiver exported  : ${receiver.exported}');
    b.writeln(
      'required permission: ${receiver.requiredPermission ?? '(none)'}',
    );
    b.writeln('sender package     : ${r.senderPackage}');
    b.writeln('delivered          : ${r.delivered}');
    b.writeln('sender authorized  : ${r.senderAuthorized}');
    b.writeln('action performed   : ${r.actionPerformed}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    // The hit: delivered to a sensitive action for an unauthorized sender.
    b.writeln('untrusted trigger  : ${r.delivered && !r.senderAuthorized}');
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // Register exported/no-permission, then a co-resident attacker forges the
    // promo broadcast and the sensitive action runs for it.
    final vulnReg = DynamicReceiverRegistry();
    final vulnReceiver = vulnReg.register(DynamicReceiverRegistry.promoAction);
    final vuln = vulnReg.deliver(
      DynamicReceiverRegistry.promoAction,
      DynamicReceiverRegistry.attackerPackage,
    );

    // RECEIVER_NOT_EXPORTED + signature permission drops the forged broadcast
    // from the untrusted co-resident app.
    final secureReg = DynamicReceiverRegistry();
    final secureReceiver = secureReg.registerSafe(
      DynamicReceiverRegistry.promoAction,
    );
    final secure = secureReg.deliver(
      DynamicReceiverRegistry.promoAction,
      DynamicReceiverRegistry.attackerPackage,
    );

    // On Android, read back what DVMA's implicitly-exported runtime receiver
    // applied from a real forged broadcast (companion attacker:
    // `am start -n com.dvma.attacker/.AttackerActivity --es send promo`).
    final applied = await BroadcastIpcBridge.applied(
      '${context.read<AppConfig>().appId}.action.APPLY_PROMO',
    );
    if (applied != null) {
      await DvmaEvidence.record(
        DynamicBroadcastReceiverExposureScreen.vulnId,
        'dynamic-receiver-applied',
        'runtime receiver applied forged broadcast: $applied',
      );
    }

    setState(() {
      _vulnResult = _render(vulnReceiver, vuln);
      _secureResult = _render(secureReceiver, secure);
      _nativeApplied = applied;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: DynamicBroadcastReceiverExposureScreen.vulnId,
      title: 'Dynamic BroadcastReceiver Exposure',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'A receiver registered at runtime with registerReceiver() but '
          'WITHOUT RECEIVER_NOT_EXPORTED (API 33+) and without a signature '
          'permission is implicitly EXPORTED. Any co-resident app can then '
          'forge a crafted broadcast to drive sensitive functionality - here a '
          'promo-apply broadcast that grants store credit. The registration '
          'FLAGS are the boundary, distinct from manifest exported receivers '
          '(Android MASTG-TEST-0366). On Android, DVMA registers such a runtime '
          'receiver and the companion attacker forges the broadcast; this '
          'screen reads back what was applied. The secure path registers '
          'RECEIVER_NOT_EXPORTED and requires a signature permission the '
          'attacker package does not hold, so the forged broadcast is dropped.',
      children: [
        DemoActionButton(
          label: 'Forge promo broadcast from co-resident app',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'exported receiver: untrusted broadcast delivered',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'not-exported + signature permission: dropped',
            value: _secureResult!,
          ),
        if (_nativeApplied != null)
          EvidencePanel(
            label: 'runtime receiver applied (from a real forged broadcast)',
            value: _nativeApplied!,
          ),
      ],
    );
  }
}
