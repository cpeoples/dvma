import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/system_provider_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'cross_profile_router.dart';

/// Cross-Profile (Work/Personal) Data & Capability Leakage.
///
/// Work (managed) and personal (primary) profiles are a security boundary, but
/// the app crosses it unsafely: a forwarded item moves between profiles with no
/// policy check and no required affordance, so a work credential leaks onto a
/// personal surface.
class CrossProfileDataCapabilityLeakageScreen extends StatefulWidget {
  const CrossProfileDataCapabilityLeakageScreen({super.key});

  static const String vulnId = 'cross_profile_data_capability_leakage';

  @override
  State<CrossProfileDataCapabilityLeakageScreen> createState() =>
      _CrossProfileDataCapabilityLeakageScreenState();
}

class _CrossProfileDataCapabilityLeakageScreenState
    extends State<CrossProfileDataCapabilityLeakageScreen> {
  final _router = CrossProfileRouter();
  // A WORK credential being forwarded to a PERSONAL surface.
  final _item = CrossProfileRouter.workCredential;
  final _dest = CrossProfileRouter.personalShareSheet;

  ForwardResult? _vuln;
  ForwardResult? _secure;
  String? _nativeLeak;

  Future<void> _run() async {
    final vuln = _router.forward(_item, Profile.work, Profile.personal, _dest);
    // Even with the user affordance "granted", policy denies sensitive work
    // data from crossing the boundary.
    final secure = _router.forwardSafe(
      _item,
      Profile.work,
      Profile.personal,
      _dest,
      userAffordanceGranted: true,
    );
    // real artifact: record the work credential value that leaked across the
    // profile boundary onto a personal surface.
    await DvmaEvidence.record(
      CrossProfileDataCapabilityLeakageScreen.vulnId,
      'cross-profile-leak',
      'work item=${_item.label} value=${_item.value} crossed '
          '${vuln.fromProfile.name}->${vuln.toProfile.name} onto '
          'surface=${vuln.surface.name} (boundaryViolated=${vuln.boundaryViolated} '
          'landedValue=${vuln.landedValue})',
    );
    if (!mounted) return;
    setState(() {
      _vuln = vuln;
      _secure = secure;
    });

    // On Android, write the WORK credential into a real shared container as the
    // "work member" and read it back as a different "personal member", a
    // genuine cross-member over-read on the real filesystem.
    final native = await SystemProviderBridge.sharedContainerLeak(
      'work.vpn.credential',
      _item.value,
    );
    if (native != null) {
      await DvmaEvidence.record(
        CrossProfileDataCapabilityLeakageScreen.vulnId,
        'cross-profile-leak-real',
        'real shared-container cross-member read: $native',
      );
      if (!mounted) return;
      setState(() => _nativeLeak = native);
    }
  }

  String get _itemDump =>
      'label     : ${_item.label}\n'
      'kind      : ${_item.kind.name}\n'
      'origin    : ${_item.origin.name} profile\n'
      'sensitive : ${_item.sensitive}\n'
      'value     : ${_item.value}\n'
      'destination: ${_dest.name} (${_dest.owner.name} profile)';

  String _render(ForwardResult r) {
    final b = StringBuffer();
    b.writeln('from profile       : ${r.fromProfile.name}');
    b.writeln('to profile         : ${r.toProfile.name}');
    b.writeln('destination surface: ${r.surface.name}');
    b.writeln('crossed boundary   : ${r.crossed}');
    b.writeln('boundary violated  : ${r.boundaryViolated}');
    b.writeln(
      'landed value       : ${r.landedValue.isEmpty ? '(none)' : r.landedValue}',
    );
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: CrossProfileDataCapabilityLeakageScreen.vulnId,
      title: 'Cross-Profile (Work/Personal) Data & Capability Leakage',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'Work (managed) and personal (primary) profiles are a security '
          'boundary, but the app crosses it unsafely. A forwarded intent / URI '
          'grant / shared item moves between profiles with NO policy check and '
          'NO required user affordance, so a WORK credential (a corporate VPN '
          'password) lands on a PERSONAL surface. This is a tenant-boundary '
          'violation on top of Android cross-profile intent-forwarding, '
          'distinct from ordinary intent redirection. This offline demo '
          'forwards an in-memory work credential to a personal share sheet. '
          'The secure path enforces a cross-profile policy - only whitelisted, '
          'non-sensitive item types may cross, with the required affordance - '
          'so the sensitive work credential is denied and never crosses.',
      children: [
        EvidencePanel(
          label: 'item being forwarded (work credential)',
          value: _itemDump,
        ),
        DemoActionButton(
          label: 'Forward work item to personal surface',
          onPressed: _run,
        ),
        if (_vuln != null)
          EvidencePanel(
            label: 'VULN no policy check (work secret crosses to personal)',
            value: _render(_vuln!),
          ),
        if (_secure != null)
          EvidencePanel(
            label: 'SECURE cross-profile policy blocks the work credential',
            value: _render(_secure!),
          ),
        if (_nativeLeak != null)
          EvidencePanel(
            label:
                'real shared-container cross-member read (device-observable)',
            value: _nativeLeak!,
          ),
      ],
    );
  }
}
