import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/component_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'privileged_deputy.dart';

/// Confused-Deputy Intent Validation Bypass.
///
/// A privileged component performs an action on behalf of a caller after only a
/// superficial Intent check, letting a local app abuse the app's privileges
/// (Android Settings CVE-2025-32326 / CVE-2025-32321 confused-deputy class).
class ConfusedDeputyIntentValidationScreen extends StatefulWidget {
  const ConfusedDeputyIntentValidationScreen({super.key});

  static const String vulnId = 'confused_deputy_intent_validation';

  @override
  State<ConfusedDeputyIntentValidationScreen> createState() =>
      _ConfusedDeputyIntentValidationScreenState();
}

class _ConfusedDeputyIntentValidationScreenState
    extends State<ConfusedDeputyIntentValidationScreen> {
  /// An unprivileged local app crafts a request for the privileged action.
  static const DeputyRequest _malicious = DeputyRequest(
    callerPackage: 'com.evil.localapp',
    callerHoldsPermission: false,
    action: PrivilegedDeputy.privilegedAction,
    targetSetting: 'adb_enabled=1',
  );

  String? _vulnResult;
  String? _secureResult;
  String? _nativeApplied;

  String _render(DeputyResult r) {
    final b = StringBuffer();
    b.writeln('performed          : ${r.performed}');
    b.writeln('on behalf of       : ${r.onBehalfOf ?? '(none)'}');
    b.writeln('setting changed    : ${r.setting ?? '(none)'}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    b.writeln('abused by unpriv.  : ${r.abusedByUnprivileged}');
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // VULN: deputy only checks the action string, not the caller.
    final vuln = PrivilegedDeputy.handle(_malicious);
    // SECURE: deputy verifies the caller holds the required permission.
    final secure = PrivilegedDeputy.handleSafe(_malicious);

    // On Android, actively start DVMA's real exported DeputyActivity in-process
    // naming only the privileged action string, and read back the setting it
    // wrote on the caller's behalf.
    final applied = await ComponentIpcBridge.startDeputy(
      setting: _malicious.targetSetting,
    );
    if (applied != null) {
      await DvmaEvidence.record(
        ConfusedDeputyIntentValidationScreen.vulnId,
        'deputy-acted-for-caller',
        'privileged deputy acted for external caller: $applied',
      );
    }

    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
      _nativeApplied = applied;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ConfusedDeputyIntentValidationScreen.vulnId,
      title: 'Confused-Deputy Intent Validation Bypass',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A PRIVILEGED, exported component performs a protected action (e.g. '
          'writing a secure setting) on behalf of a caller after only a '
          'SUPERFICIAL check: it validates the requested action string but '
          'never verifies the caller\'s identity or permission. A local, '
          'unprivileged app crafts the Intent and the deputy carries out the '
          'privileged operation for it (Android Settings CVE-2025-32326 / '
          'CVE-2025-32321 confused-deputy class). This is an offline, '
          'deterministic simulation: the deputy returns whether it performed '
          'the action and for whom. The secure path verifies the caller '
          'actually holds the required permission before acting.',
      children: [
        DemoActionButton(label: 'Send crafted Intent', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'action-only check (caller unverified)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'caller permission verified',
            value: _secureResult!,
          ),
        if (_nativeApplied != null)
          EvidencePanel(
            label: 'real exported DeputyActivity acted in-process',
            value: _nativeApplied!,
          ),
      ],
    );
  }
}
