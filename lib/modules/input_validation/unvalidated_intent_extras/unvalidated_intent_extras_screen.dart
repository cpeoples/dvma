import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/component_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Unvalidated Intent Extras.
///
/// Intent extras trusted as-is, enabling privilege escalation.
class UnvalidatedIntentExtrasScreen extends StatefulWidget {
  const UnvalidatedIntentExtrasScreen({super.key});

  static const String vulnId = 'unvalidated_intent_extras';

  @override
  State<UnvalidatedIntentExtrasScreen> createState() =>
      _UnvalidatedIntentExtrasScreenState();
}

class _UnvalidatedIntentExtrasScreenState
    extends State<UnvalidatedIntentExtrasScreen> {
  // A malicious app crafts these extras and starts the exported activity.
  final _extras = <String, String>{
    'user_id': '1',
    'is_admin': 'true',
    'redirect': 'app://internal/settings/reset',
  };
  String? _result;
  String? _nativeApplied;

  Future<void> _handle() async {
    // VULN: extras are trusted verbatim. is_admin=true grants admin; redirect
    // is followed without an allow-list.
    final isAdmin = _extras['is_admin'] == 'true';
    final result =
        'startActivity extras trusted as-is:\n'
        '  user_id=${_extras['user_id']}\n'
        '  is_admin=${_extras['is_admin']} -> '
        '${isAdmin ? "ADMIN GRANTED" : "user"}\n'
        '  redirect=${_extras['redirect']} -> navigated (no allow-list)';

    // On Android, actually start DVMA's real exported component with the
    // attacker-supplied extras, so the "extras trusted as-is" flaw crosses a
    // genuine cross-app boundary (not just an in-memory decision). The op the
    // exported handler runs on the injected extra is read back and recorded
    // under THIS module's id. Off-Android this returns null and the in-memory
    // result above is the artifact.
    final applied = await ComponentIpcBridge.startLauncher(
      cmd: _extras['is_admin'] == 'true' ? 'grant_admin' : 'noop',
    );

    setState(() {
      _result = result;
      _nativeApplied = applied;
    });
    // Real device-extractable artifact: the privilege-escalation outcome
    // driven purely by attacker-supplied extras.
    await DvmaEvidence.record(
      UnvalidatedIntentExtrasScreen.vulnId,
      'unvalidated-intent-extras',
      applied != null
          ? 'exported component trusted attacker extras: $applied'
          : result,
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: UnvalidatedIntentExtrasScreen.vulnId,
      title: 'Unvalidated Intent Extras',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'An exported activity reads Intent extras (user_id, is_admin, '
          'redirect) and trusts them without validation, so a malicious app '
          '(drozer/adb) sets is_admin=true and escalates privileges or forces '
          'an internal redirect. On Android this actually starts DVMA\'s real '
          'exported component with the attacker-supplied extras and reads back '
          'the privileged op it ran; the in-memory panel is the offline '
          'contrast. Handle the crafted intent below.',
      children: [
        EvidencePanel(
          label: 'incoming intent extras (attacker-supplied)',
          value: _extras.entries.map((e) => '${e.key}=${e.value}').join('\n'),
        ),
        DemoActionButton(label: 'Handle intent', onPressed: _handle),
        if (_result != null)
          EvidencePanel(label: 'handler result', value: _result!),
        if (_nativeApplied != null)
          EvidencePanel(
            label: 'real exported component trusted attacker extras',
            value: _nativeApplied!,
          ),
      ],
    );
  }
}
