import 'dart:async';

import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'privacy_gated_resource.dart';

/// Privacy Control Alternate-Path Bypass.
///
/// App functionality reaches protected data through an alternate path (a shared
/// app-group cache) that sidesteps the platform privacy control instead of the
/// gated, consent-checked path (iOS CVE-2026-20606 class).
class PrivacyControlAlternatePathBypassScreen extends StatefulWidget {
  const PrivacyControlAlternatePathBypassScreen({super.key});

  static const String vulnId = 'privacy_control_alternate_path_bypass';

  @override
  State<PrivacyControlAlternatePathBypassScreen> createState() =>
      _PrivacyControlAlternatePathBypassScreenState();
}

class _PrivacyControlAlternatePathBypassScreenState
    extends State<PrivacyControlAlternatePathBypassScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _fileLeak;

  String _render(PrivacyReadResult r) {
    final b = StringBuffer();
    b.writeln('source             : ${r.source}');
    b.writeln('consent checked    : ${r.consentChecked}');
    b.writeln('granted            : ${r.granted}');
    b.writeln('blocked            : ${r.blocked}');
    b.writeln('bypassed consent   : ${r.bypassedConsent}');
    if (r.reason != null) {
      b.writeln('reason             : ${r.reason}');
    }
    b.writeln('records            : ${r.records.length}');
    for (final c in r.records) {
      b.writeln('  - $c');
    }
    return b.toString().trimRight();
  }

  void _run() {
    // The user has not granted contacts consent.
    // VULN: read from the alternate app-group cache, ignoring the consent gate.
    final vuln = PrivacyGatedResource(consentGranted: false)
        .readViaAlternatePath();
    // SECURE: the single gated accessor refuses without consent, and no
    // alternate path exists.
    final secure = PrivacyGatedResource(consentGranted: false).readGated();
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // VULN (real I/O): persist the consent-bypassing contacts read to a real
    // file, then mirror to the pullable evidence sink.
    unawaited(_persist());
  }

  Future<void> _persist() async {
    final path = await PrivacyGatedResource(consentGranted: false)
        .persistAlternatePathLeak();
    final dump = PrivacyGatedResource(consentGranted: false).contacts
        .map((c) => c.toString())
        .join('\n');
    await DvmaEvidence.record(
      PrivacyControlAlternatePathBypassScreen.vulnId,
      'privacy-bypass',
      'contacts read via app-group cache (consent NOT checked):\n$dump\n'
          'written to: $path',
    );
    if (!mounted) return;
    setState(
      () => _fileLeak =
          'contacts persisted via alternate path '
          '(${PlatformLingo.current().pullable}):\n'
          '$path\n\n$dump',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PrivacyControlAlternatePathBypassScreen.vulnId,
      title: 'Privacy Control Alternate-Path Bypass',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'App functionality reaches protected data (contacts) through an '
          'ALTERNATE path - a shared app-group cache holding a copy of the same '
          'data - that sidesteps the platform privacy control instead of the '
          'gated, consent-checked path. The user\'s privacy preference is '
          'BYPASSED rather than merely over-requested (iOS CVE-2026-20606 '
          'privacy-preference bypass class). Here contacts are read from the '
          'app-group cache even though consent was never granted. This is an '
          'offline, deterministic simulation. The secure path funnels ALL reads '
          'through the single consent-checked accessor so the alternate path is '
          'closed.',
      children: [
        DemoActionButton(
          label: 'Read contacts via app-group cache',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'alternate cache read bypasses consent gate',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'single consent-checked accessor (refused)',
            value: _secureResult!,
          ),
        if (_fileLeak != null)
          EvidencePanel(
            label: 'contacts persisted via alternate path (recoverable)',
            value: _fileLeak!,
          ),
      ],
    );
  }
}
