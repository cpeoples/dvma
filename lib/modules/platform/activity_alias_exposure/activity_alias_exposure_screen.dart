import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/component_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'activity_alias_router.dart';

/// Activity Alias Exposure.
///
/// A protected internal Activity is left reachable through an exported,
/// unprotected `<activity-alias>`, so an attacker launches the sensitive
/// target through the alias even though the real component looks protected.
class ActivityAliasExposureScreen extends StatefulWidget {
  const ActivityAliasExposureScreen({super.key});

  static const String vulnId = 'activity_alias_exposure';

  @override
  State<ActivityAliasExposureScreen> createState() =>
      _ActivityAliasExposureScreenState();
}

class _ActivityAliasExposureScreenState
    extends State<ActivityAliasExposureScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeApplied;

  String _render(AliasLaunchResult r) {
    final b = StringBuffer();
    b.writeln('target activity    : ${ActivityAliasRouter.targetActivity}');
    b.writeln(
      'target exported    : ${ActivityAliasRouter.targetProtection.exported}',
    );
    b.writeln(
      'target permission  : '
      '${ActivityAliasRouter.targetProtection.requiredPermission ?? '(none)'}',
    );
    b.writeln('alias name         : ${ActivityAliasRouter.aliasName}');
    b.writeln('caller package     : ${r.callerPackage}');
    b.writeln('launched target    : ${r.launched}');
    b.writeln('target protected   : ${r.targetProtected}');
    b.writeln('alias bypass hit   : ${r.aliasBypassedProtection}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // VULN: alias exported/no-permission -> external caller reaches the
    // protected admin target through it.
    final vulnRouter = ActivityAliasRouter();
    final vuln = vulnRouter.launchViaAlias(ActivityAliasRouter.attackerPackage);

    // SECURE: alias echoes the target's protection -> external launch refused.
    final secureRouter = ActivityAliasRouter();
    final secure = secureRouter.launchViaAliasSafe(
      ActivityAliasRouter.attackerPackage,
    );

    // On Android, actively reach DVMA's not-exported ProtectedAdminActivity
    // in-process THROUGH the exported <activity-alias> and read back what the
    // protected target recorded.
    final applied = await ComponentIpcBridge.startViaAlias();
    if (applied != null) {
      await DvmaEvidence.record(
        ActivityAliasExposureScreen.vulnId,
        'protected-target-via-alias',
        'protected target reached via exported alias: $applied',
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
      vulnId: ActivityAliasExposureScreen.vulnId,
      title: 'Activity Alias Exposure',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'A protected internal Activity (exported=false, permission-guarded) '
          'is left reachable through an <activity-alias> that is itself '
          'exported=true with no permission. Alias export/permission '
          'attributes stand on their own and do NOT inherit the target\'s, so '
          'an attacker launches the sensitive target through the alias even '
          'though the real component looks protected. This is a manifest-level, '
          'deterministic misconfiguration simulated offline. The secure path '
          'makes the alias echo the target\'s protection (not exported / same '
          'permission), so the external launch is refused.',
      children: [
        DemoActionButton(
          label: 'Launch protected activity via alias',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'exported alias: protected target reached',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'alias mirrors target protection: refused',
            value: _secureResult!,
          ),
        if (_nativeApplied != null)
          EvidencePanel(
            label: 'protected target reached in-process via exported alias',
            value: _nativeApplied!,
          ),
      ],
    );
  }
}
