import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/resilience_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Frida Detection Bypass.
///
/// A real native check reads /proc/self/maps for frida libraries and probes the
/// default frida-server port (27042). The vulnerability: the app still greps a
/// fixed substring / trusts a bypassable boolean, so renaming the gadget (or
/// hooking the client gate) evades the decision.
class FridaDetectionBypassScreen extends StatefulWidget {
  const FridaDetectionBypassScreen({super.key});

  static const String vulnId = 'frida_detection_bypass';

  @override
  State<FridaDetectionBypassScreen> createState() =>
      _FridaDetectionBypassScreenState();
}

class _FridaDetectionBypassScreenState
    extends State<FridaDetectionBypassScreen> {
  // The client gate greps process maps / a fixed port for the literal "frida".
  // Rename the gadget / change the port and it sees nothing.
  bool _renamedGadget = false;
  String? _result;
  String? _nativeFinding;

  static const String _signature = 'frida-agent';

  Future<void> _check() async {
    // real native probe: reads /proc/self/maps and probes port 27042.
    final native = await ResilienceBridge.fridaCheck();
    final nativeDetected = native != null
        ? native.contains('detected=true')
        : false;

    // THE VULNERABILITY: the client-side gate only trusts a fixed substring
    // match. When "rename gadget" is on, the substring check misses even a real
    // frida hit, the bypassable boolean overrides the real native signal.
    final reported = _renamedGadget ? false : nativeDetected;

    await DvmaEvidence.record(
      FridaDetectionBypassScreen.vulnId,
      'frida',
      'nativeFinding=${native ?? "unavailable on this host (desktop/test)"} :: '
          'renamedGadget=$_renamedGadget :: reportedDetected=$reported',
    );

    if (!mounted) return;
    setState(() {
      _nativeFinding =
          native ?? 'native unavailable on this host (desktop/test)';
      _result = reported
          ? 'Frida DETECTED by real native probe.'
          : 'No Frida reported -> hooking proceeds (signature evaded / client '
                'gate bypassed).';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: FridaDetectionBypassScreen.vulnId,
      title: 'Frida Detection Bypass',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A REAL native probe scans the loaded libraries (dyld images on iOS, '
          '/proc/self/maps on Android) for frida-gadget/frida-agent/libfrida '
          'and checks the default frida port (27042). But the app collapses the '
          'decision to a fixed-substring "$_signature" match / a client-side '
          'boolean - renaming the frida-gadget (or moving the port) evades it. '
          'Toggle "rename gadget" to bypass.',
      children: [
        SwitchListTile(
          value: _renamedGadget,
          onChanged: (v) => setState(() => _renamedGadget = v),
          title: const Text('rename frida gadget'),
          activeColor: DvmaColors.accent,
        ),
        DemoActionButton(label: 'Run Frida check', onPressed: _check),
        if (_nativeFinding != null)
          EvidencePanel(label: 'native finding (real)', value: _nativeFinding!),
        if (_result != null)
          EvidencePanel(label: 'detection result', value: _result!),
      ],
    );
  }
}
