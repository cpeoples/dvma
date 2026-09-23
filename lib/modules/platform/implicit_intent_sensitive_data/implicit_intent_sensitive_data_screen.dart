import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/broadcast_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'implicit_intent_bus.dart';

/// Implicit Intent Leaks Sensitive Data.
///
/// Sensitive data is placed on an implicit intent (no explicit
/// component/package), so any co-resident app registering a matching filter
/// receives it (Samsung Smart View CVE-2025-21024 class).
class ImplicitIntentSensitiveDataScreen extends StatefulWidget {
  const ImplicitIntentSensitiveDataScreen({super.key});

  static const String vulnId = 'implicit_intent_sensitive_data';

  @override
  State<ImplicitIntentSensitiveDataScreen> createState() =>
      _ImplicitIntentSensitiveDataScreenState();
}

class _ImplicitIntentSensitiveDataScreenState
    extends State<ImplicitIntentSensitiveDataScreen> {
  static const String _action = 'com.dvma.action.SHARE_SESSION';
  static const Map<String, String> _sensitiveExtras = {
    'auth_token': 'eyJhbGciOiJIUzI1NiJ9.session-tok-9f3a',
    'account_email': 'victim@example.com',
  };

  String? _vulnResult;
  String? _secureResult;
  String? _nativeNote;

  String _render(List<IntentDelivery> deliveries) {
    return deliveries
        .map(
          (d) =>
              '${d.packageName}${d.trusted ? '' : ' [MALICIOUS]'} '
              'received: ${d.receivedExtras}',
        )
        .join('\n');
  }

  Future<void> _run() async {
    final bus = ImplicitIntentBus.withEavesdropper();
    // Implicit broadcast, every matching app (incl. the eavesdropper).
    final vuln = bus.broadcastImplicit(_action, _sensitiveExtras);
    // Explicit send addressed only to the trusted first-party app.
    final secure = bus.sendExplicit('com.dvma.app', _action, _sensitiveExtras);

    // On Android, emit the implicit broadcast so the companion attacker (which
    // claimed the same action) receives the extras across the process boundary.
    final native = await BroadcastIpcBridge.broadcastImplicitSensitive(
      _sensitiveExtras,
    );
    if (native != null) {
      await DvmaEvidence.record(
        ImplicitIntentSensitiveDataScreen.vulnId,
        'implicit-broadcast',
        '$native - extras=$_sensitiveExtras reach any app with a matching filter',
      );
    }

    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
      _nativeNote = native;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ImplicitIntentSensitiveDataScreen.vulnId,
      title: 'Implicit Intent Leaks Sensitive Data',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'Sensitive extras (an auth token and the account email) are placed on '
          'an IMPLICIT intent - one that names only an action and sets no '
          'explicit component/package - and broadcast. Android resolves an '
          'implicit intent by its action and delivers it to EVERY app that '
          'registered a matching intent-filter, so a co-resident malicious app '
          '(com.evil.eavesdropper) that claimed the same action silently '
          'receives the payload (the Samsung Smart View CVE-2025-21024 class). '
          'On Android, DVMA emits the implicit broadcast and the companion '
          'attacker (which claimed the same action) receives the extras. The '
          'secure path sends an EXPLICIT intent addressed to the single trusted '
          'package, so the eavesdropper gets nothing.',
      children: [
        DemoActionButton(label: 'Broadcast (implicit)', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'implicit broadcast (all matching apps got the data)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'explicit send (only the trusted app)',
            value: _secureResult!,
          ),
        if (_nativeNote != null)
          EvidencePanel(
            label: 'Android: implicit broadcast emitted (attacker receives)',
            value: _nativeNote!,
          ),
      ],
    );
  }
}
