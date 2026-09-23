import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/resilience_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'root_detector.dart';

/// Root/Jailbreak Detection Bypass.
///
/// A real native check (su binaries, Build.TAGS test-keys, root packages) runs
/// over the `dvma/resilience` MethodChannel. The vulnerability is that the app
/// still gates on a client-side boolean the attacker flips, so the real signal
/// is ignored the moment the bypass is on.
class RootJailbreakDetectionBypassScreen extends StatefulWidget {
  const RootJailbreakDetectionBypassScreen({super.key});

  static const String vulnId = 'root_jailbreak_detection_bypass';

  @override
  State<RootJailbreakDetectionBypassScreen> createState() =>
      _RootJailbreakDetectionBypassScreenState();
}

class _RootJailbreakDetectionBypassScreenState
    extends State<RootJailbreakDetectionBypassScreen> {
  final _detector = RootDetector();
  String? _result;
  String? _nativeFinding;

  Future<void> _check() async {
    // real native probe: reads su paths, Build.TAGS, installed root packages.
    final native = await ResilienceBridge.rootCheck();
    // Off-Android (tests/iOS/desktop) the bridge returns null -> fall back to
    // the in-memory indicator model so the demo still runs.
    final indicatorsPresent = native != null
        ? native.contains('compromised=true')
        : true;

    // THE VULNERABILITY: the app trusts a client-side boolean. When the
    // attacker flips [bypassed] (frida/objection), the real finding is ignored.
    final compromised = _detector.isCompromised(
      indicatorsPresent: indicatorsPresent,
    );

    await DvmaEvidence.record(
      RootJailbreakDetectionBypassScreen.vulnId,
      'root',
      'nativeFinding=${native ?? "unavailable on this host (desktop/test)"} :: '
          'bypassed=${_detector.bypassed} :: gateResult=$compromised',
    );

    if (!mounted) return;
    setState(() {
      _nativeFinding =
          native ?? 'native unavailable on this host (desktop/test)';
      _result = compromised
          ? 'Rooted device DETECTED -> app should refuse to run.'
          : 'Device reported CLEAN -> app runs (client-side gate bypassed, '
                'real native signal ignored).';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: RootJailbreakDetectionBypassScreen.vulnId,
      title: 'Root/Jailbreak Detection Bypass',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'A REAL native check runs on-device (su binaries, Build.TAGS '
          'test-keys, installed root managers). But the app collapses the '
          'decision to a single client-side boolean - an attacker hooks the '
          'function (frida/objection) or patches the flag to false and the '
          'device is reported clean regardless of the real finding. Toggle the '
          '"frida hook" to bypass it.',
      children: [
        SwitchListTile(
          value: _detector.bypassed,
          onChanged: (v) => setState(() => _detector.bypassed = v),
          title: const Text('frida hook: force not-rooted'),
          activeColor: DvmaColors.accent,
        ),
        DemoActionButton(label: 'Run root check', onPressed: _check),
        EvidencePanel(
          label: 'indicators checked',
          value: RootDetector.indicators.join('\n'),
        ),
        if (_nativeFinding != null)
          EvidencePanel(label: 'native finding (real)', value: _nativeFinding!),
        if (_result != null)
          EvidencePanel(label: 'detection result', value: _result!),
      ],
    );
  }
}
