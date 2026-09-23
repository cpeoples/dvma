import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/component_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'task_stack_manager.dart';

/// Activity Task Stack Hijacking (StrandHogg-style).
///
/// Loose task affinity / reparenting lets a malicious activity insert itself
/// into a trusted app's task, so returning to the victim app surfaces the
/// attacker's phishing screen inside the victim flow.
class ActivityTaskStackHijackingScreen extends StatefulWidget {
  const ActivityTaskStackHijackingScreen({super.key});

  static const String vulnId = 'activity_task_stack_hijacking';

  @override
  State<ActivityTaskStackHijackingScreen> createState() =>
      _ActivityTaskStackHijackingScreenState();
}

class _ActivityTaskStackHijackingScreenState
    extends State<ActivityTaskStackHijackingScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeApplied;

  String _render(TaskLaunchResult r) {
    final b = StringBuffer();
    b.writeln('malicious activity : ${r.activity.name}');
    b.writeln('declared affinity  : ${r.activity.taskAffinity}');
    b.writeln('allowReparenting   : ${r.activity.allowTaskReparenting}');
    b.writeln('victim affinity    : ${TaskStackManager.victimAffinity}');
    b.writeln('landed in task     : ${r.landedInTaskAffinity}');
    b.writeln('top of victim stack: ${r.topOfVictimStack}');
    b.writeln('appears in victim  : ${r.appearsInVictimTask}');
    b.writeln('hijacked           : ${r.hijacked}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // VULN: victim task is seeded, then the malicious activity declaring the
    // victim's affinity is launched atop the victim's back-stack.
    final vulnMgr = TaskStackManager()..seedVictimTask();
    final vuln = vulnMgr.launch(TaskStackManager.maliciousActivity);

    // SECURE: unique per-app affinity + no reparenting forces the malicious
    // activity into its own isolated task.
    final secureMgr = TaskStackManager()..seedVictimTask();
    final secure = secureMgr.launchSafe(TaskStackManager.maliciousActivity);

    // On Android, actively start DVMA's real shared-taskAffinity
    // HijackTargetActivity in-process; its placement (taskAffinity=com.dvma,
    // launchMode=standard) is observable in `dumpsys activity activities`.
    final applied = await ComponentIpcBridge.startTaskHijackTarget();
    if (applied != null) {
      await DvmaEvidence.record(
        ActivityTaskStackHijackingScreen.vulnId,
        'shared-affinity-task',
        'DVMA screen uses a shared task affinity a co-resident app can join: $applied',
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
      vulnId: ActivityTaskStackHijackingScreen.vulnId,
      title: 'Activity Task Stack Hijacking',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'Loose task affinity and launch modes (a malicious Activity '
          'declaring the victim app\'s taskAffinity with singleTask / '
          'allowTaskReparenting) let the attacker insert itself into a trusted '
          'app\'s task and back-stack. When the user returns to the victim app '
          'they are shown the attacker\'s phishing screen inside the victim '
          'flow (StrandHogg). This is TASK-STACK PLACEMENT, distinct from a '
          'drawn tapjacking overlay, simulated offline and deterministically. '
          'The secure path enforces a unique per-app affinity and disallows '
          'reparenting, forcing the malicious activity into its own task so it '
          'can never appear in the victim flow.',
      children: [
        DemoActionButton(
          label: 'Launch malicious activity into victim task',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'shared affinity: attacker lands in victim task',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'unique affinity: attacker isolated to own task',
            value: _secureResult!,
          ),
        if (_nativeApplied != null)
          EvidencePanel(
            label: 'real shared-affinity activity started (dumpsys observable)',
            value: _nativeApplied!,
          ),
      ],
    );
  }
}
