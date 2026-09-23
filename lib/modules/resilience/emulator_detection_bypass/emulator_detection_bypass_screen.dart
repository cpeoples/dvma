import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/resilience_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Emulator Detection Bypass.
///
/// A real native check reads the device's Build fields (FINGERPRINT/MODEL/
/// MANUFACTURER/PRODUCT/HARDWARE) for emulator markers. The vulnerability: the
/// app still trusts a bypassable boolean, so spoofing the props / hooking the
/// gate defeats it.
class EmulatorDetectionBypassScreen extends StatefulWidget {
  const EmulatorDetectionBypassScreen({super.key});

  static const String vulnId = 'emulator_detection_bypass';

  @override
  State<EmulatorDetectionBypassScreen> createState() =>
      _EmulatorDetectionBypassScreenState();
}

class _EmulatorDetectionBypassScreenState
    extends State<EmulatorDetectionBypassScreen> {
  // The client gate just reads build properties, which frida/build.prop edits
  // spoof.
  bool _spoofed = false;
  String? _result;
  String? _nativeFinding;

  Future<void> _check() async {
    // real native probe: inspects Build.FINGERPRINT/MODEL/MANUFACTURER/etc.
    final native = await ResilienceBridge.emulatorCheck();
    // Off-Android fallback: assume the virtual-looking props of the old model.
    final nativeEmulator = native != null
        ? native.contains('emulator=true')
        : true;

    // THE VULNERABILITY: the app trusts a client-side boolean. With "spoof
    // props" on, the real emulator finding is overridden and reported physical.
    final reported = _spoofed ? false : nativeEmulator;

    await DvmaEvidence.record(
      EmulatorDetectionBypassScreen.vulnId,
      'emulator',
      'nativeFinding=${native ?? "unavailable on this host (desktop/test)"} :: '
          'spoofed=$_spoofed :: reportedEmulator=$reported',
    );

    if (!mounted) return;
    setState(() {
      _nativeFinding =
          native ?? 'native unavailable on this host (desktop/test)';
      _result = reported
          ? 'Emulator DETECTED (real Build fields look virtual).'
          : 'Physical device reported (props spoofed / gate bypassed) -> '
                'analysis continues.';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: EmulatorDetectionBypassScreen.vulnId,
      title: 'Emulator Detection Bypass',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'A REAL native probe reads Build.FINGERPRINT / MODEL / MANUFACTURER / '
          'PRODUCT / HARDWARE for generic/goldfish/ranchu/sdk/emulator markers. '
          'But the app collapses the decision to a client-side boolean - those '
          'props are trivially spoofed by editing build.prop or hooking the '
          'getters. Toggle "spoof props" to defeat it.',
      children: [
        SwitchListTile(
          value: _spoofed,
          onChanged: (v) => setState(() => _spoofed = v),
          title: const Text('spoof build props (real device)'),
          activeColor: DvmaColors.accent,
        ),
        DemoActionButton(label: 'Run emulator check', onPressed: _check),
        if (_nativeFinding != null)
          EvidencePanel(
            label: 'build fields read (real)',
            value: _nativeFinding!,
          ),
        if (_result != null)
          EvidencePanel(label: 'detection result', value: _result!),
      ],
    );
  }
}
