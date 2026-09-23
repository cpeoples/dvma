import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/component_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'intent_model.dart';

/// Intent Redirection / Task Hijack (StrandHogg-style).
///
/// An exported component forwards an attacker-supplied nested intent to an
/// internal component with no validation (intent redirection).
class IntentRedirectionScreen extends StatefulWidget {
  const IntentRedirectionScreen({super.key});

  static const String vulnId = 'intent_redirection';

  @override
  State<IntentRedirectionScreen> createState() =>
      _IntentRedirectionScreenState();
}

class _IntentRedirectionScreenState extends State<IntentRedirectionScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeApplied;

  Future<void> _run() async {
    // Attacker sends a benign-looking intent to the exported component, but
    // hides a nested intent targeting an INTERNAL component in the extras.
    final attackerIntent = AppIntent(
      action: 'android.intent.action.VIEW',
      target: 'ExportedProxyActivity',
      extras: {
        'forward_intent': AppIntent(
          action: 'com.dvma.ADMIN',
          target: 'InternalAdminActivity',
        ),
      },
    );

    final vuln = IntentRouter.handleExported(attackerIntent);
    final secure = IntentRouter.secureHandleExported(attackerIntent);

    // On Android, actively start DVMA's real exported ProxyActivity in-process
    // with a nested forward Intent targeting the not-exported
    // InternalAdminActivity, and read back the redirection it performed.
    final applied = await ComponentIpcBridge.startRedirection();
    if (applied != null) {
      await DvmaEvidence.record(
        IntentRedirectionScreen.vulnId,
        'redirected-to-internal',
        'exported proxy redirected external caller to internal target: $applied',
      );
    }

    setState(() {
      _vulnResult =
          'dispatched to: ${vuln.dispatchedTo}\nredirected: ${vuln.redirected}';
      _secureResult = 'dispatched to: ${secure.dispatchedTo}';
      _nativeApplied = applied;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: IntentRedirectionScreen.vulnId,
      title: 'Intent Redirection',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'An exported component extracts a nested "forward" intent from '
          'attacker-supplied extras and dispatches it with no target '
          'validation, letting an external caller reach an internal-only '
          'component through the app\'s own privileges. This is a Dart '
          'simulation; the real exploit is Android-level (an exported Activity '
          'forwarding getParcelableExtra("intent")).',
      children: [
        DemoActionButton(
          label: 'Send attacker intent to exported component',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'vulnerable exported handler',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'what a validating handler would do',
            value: _secureResult!,
          ),
        if (_nativeApplied != null)
          EvidencePanel(
            label: 'real exported ProxyActivity redirected to internal target',
            value: _nativeApplied!,
          ),
      ],
    );
  }
}
