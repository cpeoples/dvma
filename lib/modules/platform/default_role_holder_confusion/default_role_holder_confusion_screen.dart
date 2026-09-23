import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/broadcast_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'role_resolver.dart';

/// Default-Role / Role-Holder Confusion.
///
/// The app resolves a system role via implicit intent and trusts whichever
/// activity the OS returns, delivering a secret without checking the
/// authoritative RoleManager holder or pinning the target's signature. A
/// co-resident app that out-prioritizes the real default steals the secret.
class DefaultRoleHolderConfusionScreen extends StatefulWidget {
  const DefaultRoleHolderConfusionScreen({super.key});

  static const String vulnId = 'default_role_holder_confusion';

  @override
  State<DefaultRoleHolderConfusionScreen> createState() =>
      _DefaultRoleHolderConfusionScreenState();
}

class _DefaultRoleHolderConfusionScreenState
    extends State<DefaultRoleHolderConfusionScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeNote;

  String _renderVuln(RoleDelegationResult r) {
    final b = StringBuffer();
    b.writeln('requested role     : ${r.role}');
    b.writeln('RoleManager holder : ${RoleResolver.roleManagerHolder}');
    b.writeln('recipient package  : ${r.recipientPackage}');
    b.writeln('role holder verified: ${r.roleHolderVerified}');
    b.writeln('delivered          : ${r.delivered}');
    b.writeln('secret delivered   : ${r.deliveredSecret ?? '(none)'}');
    b.writeln(
      'confused-deputy hit: '
      '${r.delivered && !r.roleHolderVerified && r.recipientPackage == RoleResolver.attackerPackage}',
    );
    return b.toString().trimRight();
  }

  String _renderSecure(RoleDelegationResult r) {
    final b = StringBuffer();
    b.writeln('requested role     : ${r.role}');
    b.writeln('RoleManager holder : ${RoleResolver.roleManagerHolder}');
    b.writeln('resolved recipient : ${r.recipientPackage}');
    b.writeln('role holder verified: ${r.roleHolderVerified}');
    b.writeln('delivered          : ${r.delivered}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    b.writeln('confused-deputy hit: ${r.delivered && !r.roleHolderVerified}');
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // Resolve the role via implicit intent and deliver the secret to the
    // highest-priority matching app - the attacker registered the same filter.
    final vulnResolver = RoleResolver();
    final vuln = vulnResolver.delegateSecret(RoleResolver.role);

    // Verify the resolved target is the authoritative RoleManager holder and
    // matches the pinned package + signature before delegating.
    final secureResolver = RoleResolver();
    final secure = secureResolver.delegateSecretSafe(RoleResolver.role);

    // On Android, broadcast the role-delegation secret implicitly; the
    // companion attacker's higher-priority filter receives it.
    final native = await BroadcastIpcBridge.delegateRole(RoleResolver.secret);
    if (native != null) {
      await DvmaEvidence.record(
        DefaultRoleHolderConfusionScreen.vulnId,
        'role-delegate',
        '$native - secret sent to the resolved default role holder',
      );
    }

    setState(() {
      _vulnResult = _renderVuln(vuln);
      _secureResult = _renderSecure(secure);
      _nativeNote = native;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: DefaultRoleHolderConfusionScreen.vulnId,
      title: 'Default-Role / Role-Holder Confusion',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The app resolves a system role (default browser / dialer / SMS / '
          'wallet / credential provider / NFC) with resolveActivity() or an '
          'implicit intent and TRUSTS whichever app the OS returns, handing it '
          'a sensitive URI / credential - without checking the authoritative '
          'RoleManager role holder or pinning the target package + signature '
          '(CWE-346 / CWE-940 / CWE-284). A co-resident app that registers the '
          'matching intent-filter with a higher priority becomes the resolved '
          'default and receives the secret. On Android, DVMA broadcasts the '
          'secret to the resolved default holder and the companion attacker '
          'receives it. The secure path consults RoleManager for the real '
          'holder and pins package + signature, refusing an unexpected holder.',
      children: [
        DemoActionButton(
          label: 'Delegate secret to default role holder',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'trusted resolution: attacker becomes default',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'RoleManager + signature pin: unexpected holder refused',
            value: _secureResult!,
          ),
        if (_nativeNote != null)
          EvidencePanel(
            label: 'Android: secret broadcast to resolved default (attacker receives)',
            value: _nativeNote!,
          ),
      ],
    );
  }
}
