import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/resilience_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Anti-Debugging Bypass.
///
/// A real native check queries android.os.Debug.isDebuggerConnected() and the
/// FLAG_DEBUGGABLE app flag. The vulnerability: the decision still hinges on a
/// single client-side boolean an attacker NOPs/hooks to false.
class AntiDebuggingBypassScreen extends StatefulWidget {
  const AntiDebuggingBypassScreen({super.key});

  static const String vulnId = 'anti_debugging_bypass';

  @override
  State<AntiDebuggingBypassScreen> createState() =>
      _AntiDebuggingBypassScreenState();
}

class _AntiDebuggingBypassScreenState extends State<AntiDebuggingBypassScreen> {
  // The anti-debug gate is one boolean. An attacker NOPs it / hooks it to
  // return false.
  bool _hookedToFalse = false;
  String? _result;
  String? _nativeFinding;

  Future<void> _check() async {
    // real native probe: Debug.isDebuggerConnected() + FLAG_DEBUGGABLE.
    final native = await ResilienceBridge.debuggerCheck();
    // Off-Android fallback: pretend a debugger is attached so the demo runs.
    final nativeDetected = native != null
        ? native.contains('detected=true')
        : true;

    // THE VULNERABILITY: everything hinges on one return value. When
    // "patched" is on, the real native detection is discarded.
    final reported = _hookedToFalse ? false : nativeDetected;

    await DvmaEvidence.record(
      AntiDebuggingBypassScreen.vulnId,
      'debugger',
      'nativeFinding=${native ?? "unavailable on this host (desktop/test)"} :: '
          'hookedToFalse=$_hookedToFalse :: reportedDetected=$reported',
    );

    if (!mounted) return;
    setState(() {
      _nativeFinding =
          native ?? 'native unavailable on this host (desktop/test)';
      _result = reported
          ? 'Debugger DETECTED by real native probe -> app should exit.'
          : 'No debugger reported -> continues (check patched out / gate '
                'bypassed).';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: AntiDebuggingBypassScreen.vulnId,
      title: 'Anti-Debugging Bypass',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A REAL native probe calls Debug.isDebuggerConnected() and reads the '
          'FLAG_DEBUGGABLE app flag. But the protection still collapses to a '
          'single isDebuggerAttached() return value - an attacker NOPs it or '
          'hooks it to false and debugs freely. Toggle to simulate patching the '
          'check.',
      children: [
        SwitchListTile(
          value: _hookedToFalse,
          onChanged: (v) => setState(() => _hookedToFalse = v),
          title: const Text('patch isDebuggerAttached() -> false'),
          activeColor: DvmaColors.accent,
        ),
        DemoActionButton(label: 'Run anti-debug check', onPressed: _check),
        if (_nativeFinding != null)
          EvidencePanel(label: 'native finding (real)', value: _nativeFinding!),
        if (_result != null)
          EvidencePanel(label: 'detection result', value: _result!),
      ],
    );
  }
}
