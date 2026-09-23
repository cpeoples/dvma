import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/broadcast_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'capability_composition_chain.dart';

/// Android Capability-Composition Chain.
///
/// The vulnerability is the composition, not any single hop: an untrusted
/// notification action -> mutable PendingIntent -> exported receiver -> bound
/// Binder service -> privileged transfer, each hop trusting its predecessor.
class AndroidCapabilityCompositionChainScreen extends StatefulWidget {
  const AndroidCapabilityCompositionChainScreen({super.key});

  static const String vulnId = 'android_capability_composition_chain';

  @override
  State<AndroidCapabilityCompositionChainScreen> createState() =>
      _AndroidCapabilityCompositionChainScreenState();
}

class _AndroidCapabilityCompositionChainScreenState
    extends State<AndroidCapabilityCompositionChainScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeApplied;

  String _render(ChainResult r) {
    final b = StringBuffer();
    for (var i = 0; i < r.hops.length; i++) {
      final h = r.hops[i];
      final note = h.reauthorized
          ? 're-authorizes original caller'
          : (h.trustedPredecessor ? 'trusts predecessor' : 'hardened');
      b.writeln('hop ${i + 1}: ${h.name}  ->  $note');
    }
    b.writeln('transfer performed        : ${r.transferPerformed}');
    b.writeln('original caller reauthed  : ${r.originalCallerReauthorized}');
    b.writeln('amount / to               : ${r.amount} -> ${r.toAccount}');
    if (r.denyReason != null) {
      b.writeln('deny reason               : ${r.denyReason}');
    }
    b.writeln('chain exploited           : ${r.chainExploited}');
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    final chain = CapabilityCompositionChain();
    // On Android, actively fire DVMA's real exported ChainEntryReceiver
    // in-process so the mutable-PI -> receiver -> bound service -> transfer sink
    // chain runs end-to-end, then read back the sink's recorded outcome.
    final applied = await BroadcastIpcBridge.fireChain();
    if (applied != null) {
      await DvmaEvidence.record(
        AndroidCapabilityCompositionChainScreen.vulnId,
        'chain-reached-sink',
        'external trigger laundered through the chain to the privileged sink: $applied',
      );
    }
    setState(() {
      _vulnResult = _render(
        chain.run(CapabilityCompositionChain.attackerCaller),
      );
      _secureResult = _render(
        chain.runSafe(CapabilityCompositionChain.attackerCaller),
      );
      _nativeApplied = applied;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: AndroidCapabilityCompositionChainScreen.vulnId,
      title: 'Android Capability-Composition Chain',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'No single hop is the bug - the COMPOSITION is. A notification action '
          'carries a mutable PendingIntent, which fires an exported '
          'BroadcastReceiver, which binds an exported Binder service, which '
          'performs a privileged transfer. Each hop trusts its immediate '
          'predecessor instead of re-checking the ORIGINAL caller, so an '
          'attacker who triggers the first hop launders an unauthenticated '
          'request through four individually-benign links into a privileged '
          'operation (CWE-441 confused deputy). This is an offline, '
          'deterministic simulation. The secure path propagates and '
          're-authorizes the original caller at the sink and uses '
          'immutable/explicit intents + per-method authorization, breaking the '
          'chain at the first untrusted hop.',
      children: [
        DemoActionButton(
          label: 'Trigger chain from untrusted notification',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'composed chain: untrusted trigger reaches the sink',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'per-hop authorization: chain breaks early',
            value: _secureResult!,
          ),
        if (_nativeApplied != null)
          EvidencePanel(
            label: 'real chain fired in-process: trigger reaches the sink',
            value: _nativeApplied!,
          ),
      ],
    );
  }
}
