import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/native/broadcast_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'broadcast_bus.dart';

/// Exported BroadcastReceiver Data Spoofing.
///
/// An exported BroadcastReceiver accepts broadcasts from any app and trusts
/// their extras, so a local app spoofs data the app treats as authoritative
/// (e.g. device location) (Home Assistant Companion GHSA location-spoof class).
class ExportedBroadcastReceiverSpoofScreen extends StatefulWidget {
  const ExportedBroadcastReceiverSpoofScreen({super.key});

  static const String vulnId = 'exported_broadcast_receiver_spoof';

  @override
  State<ExportedBroadcastReceiverSpoofScreen> createState() =>
      _ExportedBroadcastReceiverSpoofScreenState();
}

class _ExportedBroadcastReceiverSpoofScreenState
    extends State<ExportedBroadcastReceiverSpoofScreen> {
  // A spoofed location broadcast from a co-resident malicious app.
  static const Broadcast _spoofedBroadcast = Broadcast(
    action: BroadcastBus.locationAction,
    senderPackage: 'com.evil.locationspoof',
    senderHoldsPermission: false,
    extras: {
      'lat': '40.6892',
      'lon': '-74.0445',
      'label': 'Statue of Liberty (spoofed)',
    },
  );

  String? _vulnResult;
  String? _secureResult;
  String? _nativeApplied;

  String _render(ReceiveResult r, Broadcast b, Set<String> trusted) {
    final sb = StringBuffer();
    sb.writeln('action        : ${b.action}');
    sb.writeln('sender        : ${b.senderPackage}');
    sb.writeln('holds perm    : ${b.senderHoldsPermission}');
    sb.writeln('accepted      : ${r.accepted}');
    sb.writeln('blocked       : ${r.blocked}');
    if (r.blockReason != null) {
      sb.writeln('block reason  : ${r.blockReason}');
    }
    if (r.appliedExtras != null) {
      sb.writeln('applied extras: ${r.appliedExtras}');
    }
    sb.writeln('spoof accepted: ${r.spoofAccepted(b, trusted)}');
    return sb.toString().trimRight();
  }

  Future<void> _run() async {
    final bus = BroadcastBus();

    // The exported receiver trusts the spoofed extras.
    final vuln = bus.deliver(_spoofedBroadcast);

    // The sender package + signature-permission check rejects the spoof.
    final secure = bus.deliverSafe(_spoofedBroadcast);

    // On Android, read back what DVMA's exported receiver last applied from a
    // real broadcast (fired by the companion attacker via
    // `am start -n com.dvma.attacker/.AttackerActivity --es send location`).
    final applied = await BroadcastIpcBridge.applied(
      '${context.read<AppConfig>().appId}.action.LOCATION_UPDATE',
    );
    if (applied != null) {
      await DvmaEvidence.record(
        ExportedBroadcastReceiverSpoofScreen.vulnId,
        'exported-receiver-applied',
        'exported receiver applied attacker extras: $applied',
      );
    }

    setState(() {
      _vulnResult = _render(vuln, _spoofedBroadcast, bus.trustedSenders);
      _secureResult = _render(secure, _spoofedBroadcast, bus.trustedSenders);
      _nativeApplied = applied;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ExportedBroadcastReceiverSpoofScreen.vulnId,
      title: 'Exported BroadcastReceiver Data Spoofing',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The app registers a BroadcastReceiver that is EXPORTED with no '
          'signature-level permission, so any app on the device can send it a '
          'broadcast. The receiver trusts the extras it receives as '
          'authoritative - a device-location update - and updates app state '
          'from them. A local app (com.dvma.attacker) sends a spoofed '
          'LOCATION_UPDATE and the app believes the fake coordinates (Home '
          'Assistant Companion GHSA location-spoof class). On Android, DVMA '
          'registers a matching exported receiver; the companion attacker fires '
          'the broadcast and this screen reads back the applied extras. The '
          'secure path verifies the sender is a trusted first-party package AND '
          'holds the app\'s signature-level permission before applying any extras.',
      children: [
        DemoActionButton(
          label: 'Send spoofed location broadcast (com.evil.*)',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'exported receiver (trusts any sender)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'validated: sender package + signature permission',
            value: _secureResult!,
          ),
        if (_nativeApplied != null)
          EvidencePanel(
            label: 'exported receiver applied (from a real attacker send)',
            value: _nativeApplied!,
          ),
      ],
    );
  }
}
