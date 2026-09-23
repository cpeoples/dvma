import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'notification_center.dart';

/// Exported Component -> Unauthorized State Manipulation.
///
/// An exported component accepts an attacker-controlled notification id in its
/// intent extras and cancels it with no caller/ownership check, so a co-resident
/// app mutates state it does not own (Datadog Android CVE-2026-47361 class).
class ExportedComponentStateManipulationScreen extends StatefulWidget {
  const ExportedComponentStateManipulationScreen({super.key});

  static const String vulnId = 'exported_component_state_manipulation';

  @override
  State<ExportedComponentStateManipulationScreen> createState() =>
      _ExportedComponentStateManipulationScreenState();
}

class _ExportedComponentStateManipulationScreenState
    extends State<ExportedComponentStateManipulationScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeApplied;

  String _render(NotificationCenter center, ControllerResult r) {
    final b = StringBuffer();
    b.writeln('caller             : ${r.caller}');
    b.writeln('target id          : ${r.targetId}');
    b.writeln('target owner       : ${r.targetOwner ?? '(none)'}');
    b.writeln('state mutated      : ${r.mutated}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    b.writeln('cross-owner mutate : ${r.crossOwnerMutation}');
    b.writeln(
      "victim notif active: "
      '${center.isActive(NotificationCenter.victimNotificationId)}',
    );
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // VULN: the attacker cancels the VICTIM's notification with no ownership
    // check.
    final vulnCenter = NotificationCenter.seeded();
    final vuln = vulnCenter.handleIntent(
      NotificationCenter.attackerPackage,
      NotificationCenter.victimNotificationId,
    );
    // SECURE: the same crafted intent is refused because the attacker does not
    // own the target notification.
    final secureCenter = NotificationCenter.seeded();
    final secure = secureCenter.handleIntentSafe(
      NotificationCenter.attackerPackage,
      NotificationCenter.victimNotificationId,
    );

    // On Android, post two real Notifications then drive the exported
    // StateControlActivity in-process to cancel the victim by id (no ownership
    // check), the victim notification actually disappears from the shade.
    final applied = await PlatformIpcBridge.stateManipulation();
    if (applied != null) {
      await DvmaEvidence.record(
        ExportedComponentStateManipulationScreen.vulnId,
        'exported-activity-mutated-state',
        'exported component mutated state for external caller: $applied',
      );
    }

    setState(() {
      _vulnResult = _render(vulnCenter, vuln);
      _secureResult = _render(secureCenter, secure);
      _nativeApplied = applied;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ExportedComponentStateManipulationScreen.vulnId,
      title: 'Exported Component -> Unauthorized State Manipulation',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'An EXPORTED component accepts an attacker-controlled notification id '
          'in its intent extras and performs a security-sensitive STATE CHANGE '
          '(cancelling the notification) with NO caller/ownership validation. '
          'Because it is exported, a co-resident unprivileged app '
          '(com.evil.localapp) sends an intent naming the VICTIM AI-chat app\'s '
          'notification id and the system cancels it on the attacker\'s behalf '
          '(the Datadog Android CVE-2026-47361 class) - suppressing an alert the '
          'attacker does not own. This is an offline, deterministic simulation: '
          'an in-memory NotificationCenter holds notifications owned by package '
          'ids. The secure path verifies the notification\'s owner package '
          'matches the caller (or a signature permission) before mutating, so '
          'the cross-owner request is refused and the victim\'s notification '
          'stays active.',
      children: [
        DemoActionButton(label: 'Send crafted cancel intent', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'no ownership check (victim notif cancelled)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'owner package verified (refused)',
            value: _secureResult!,
          ),
        if (_nativeApplied != null)
          EvidencePanel(
            label: 'real Notifications posted; victim cancelled in-process',
            value: _nativeApplied!,
          ),
      ],
    );
  }
}
