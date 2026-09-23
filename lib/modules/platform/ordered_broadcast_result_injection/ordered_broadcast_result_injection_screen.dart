import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/native/broadcast_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'ordered_broadcast_bus.dart';

/// Ordered-Broadcast Result Injection.
///
/// The app sends an ordered broadcast and TRUSTS the aggregated result for a
/// security decision, but a higher-priority co-resident receiver runs first and
/// rewrites the result, poisoning the entitlement the app consumes.
class OrderedBroadcastResultInjectionScreen extends StatefulWidget {
  const OrderedBroadcastResultInjectionScreen({super.key});

  static const String vulnId = 'ordered_broadcast_result_injection';

  @override
  State<OrderedBroadcastResultInjectionScreen> createState() =>
      _OrderedBroadcastResultInjectionScreenState();
}

class _OrderedBroadcastResultInjectionScreenState
    extends State<OrderedBroadcastResultInjectionScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(OrderedBroadcastResult r) {
    final b = StringBuffer();
    b.writeln('action             : ${r.action}');
    b.writeln('first receiver     : ${r.firstReceiverPackage ?? '(none)'}');
    b.writeln('attacker package   : ${OrderedBroadcastBus.attackerPackage}');
    b.writeln('attacker priority  : ${OrderedBroadcastBus.attackerPriority}');
    b.writeln('legit result       : ${OrderedBroadcastBus.legitimateResult}');
    b.writeln('final value        : ${r.finalValue}');
    b.writeln('result trusted     : ${r.resultTrusted}');
    b.writeln('result poisoned    : ${r.resultPoisoned}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    final action =
        '${context.read<AppConfig>().appId}.action.ENTITLEMENT_CHECK';

    // Unguarded ordered broadcast; attacker receiver has higher priority and
    // rewrites the result the app trusts for the entitlement decision.
    final vulnBus = OrderedBroadcastBus()
      ..register(OrderedBroadcastBus.attackerReceiver())
      ..register(OrderedBroadcastBus.appReceiver());
    final vuln = vulnBus.sendOrdered(OrderedBroadcastBus.legitimateResult);

    // Signature-permission-guarded broadcast drops the attacker, and the
    // ordered result is never trusted for the security decision.
    final secureBus = OrderedBroadcastBus()
      ..register(OrderedBroadcastBus.attackerReceiver())
      ..register(OrderedBroadcastBus.appReceiver());
    final secure = secureBus.sendOrderedSafe(
      OrderedBroadcastBus.legitimateResult,
    );

    // On Android, send the ordered broadcast; the companion attacker's
    // higher-priority receiver rewrites the result before DVMA's final
    // receiver aggregates it. The guarded form excludes the unsigned attacker.
    await BroadcastIpcBridge.sendOrdered(OrderedBroadcastBus.legitimateResult);
    final nativeResult = await BroadcastIpcBridge.applied(action);
    if (nativeResult != null) {
      await DvmaEvidence.record(
        OrderedBroadcastResultInjectionScreen.vulnId,
        'ordered-result',
        'aggregated ordered-broadcast result the app trusts: $nativeResult',
      );
    }

    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
      _nativeResult = nativeResult;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: OrderedBroadcastResultInjectionScreen.vulnId,
      title: 'Ordered-Broadcast Result Injection',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The app sends an ordered broadcast and then trusts the aggregated '
          'getResultData()/result-extras for a security decision (isPremium / '
          'allowTransfer). Ordered broadcasts are delivered in priority order, '
          'so a co-resident receiver registered at a HIGHER priority runs first '
          'and calls setResultData()/setResultExtras() to poison the result '
          'before the app aggregates it. The attacker sits in the middle of the '
          'app\'s own broadcast pipeline, so the "authoritative" result is '
          'attacker-controlled. The secure path guards the broadcast with a '
          'signature permission (so the attacker receiver never runs) and never '
          'uses an ordered-broadcast result as the source of a security '
          'decision.',
      children: [
        DemoActionButton(label: 'Broadcast entitlement check', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'higher-priority receiver: result poisoned',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'signature-guarded + untrusted result: safe',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'Android: ordered result after attacker reorder',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
