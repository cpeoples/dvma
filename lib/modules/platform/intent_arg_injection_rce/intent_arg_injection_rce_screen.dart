import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/component_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'arg_injection_launcher.dart';

/// Intent Argument Injection -> Local Code Execution.
///
/// An exported component feeds an attacker-controlled intent extra /
/// command-line arg into an execution path, so another app runs code with this
/// app's privileges (Unity CVE-2025-59489 class).
class IntentArgInjectionRceScreen extends StatefulWidget {
  const IntentArgInjectionRceScreen({super.key});

  static const String vulnId = 'intent_arg_injection_rce';

  @override
  State<IntentArgInjectionRceScreen> createState() =>
      _IntentArgInjectionRceScreenState();
}

class _IntentArgInjectionRceScreenState
    extends State<IntentArgInjectionRceScreen> {
  final TextEditingController _controller = TextEditingController(
    text: 'cmd=dump_secrets',
  );

  String? _vulnResult;
  String? _secureResult;
  String? _nativeApplied;

  /// Parse a raw "adb am"-style extra string (key=value) into intent extras.
  Map<String, String> _parseExtras() {
    final raw = _controller.text.trim();
    final idx = raw.indexOf('=');
    if (idx <= 0) {
      // Support the "-xrun/path" flag style with no '='.
      if (raw.startsWith('-xrun')) {
        return {'-xrun': raw.substring('-xrun'.length)};
      }
      return {'action': raw};
    }
    return {raw.substring(0, idx): raw.substring(idx + 1)};
  }

  Future<void> _deliver() async {
    final extras = _parseExtras();
    final vuln = ArgInjectionLauncher.handleIntent(extras);
    final secure = ArgInjectionLauncher.handleIntentSecure(extras);

    // On Android, actively start DVMA's real exported LauncherActivity
    // in-process with the injected cmd extra and read back the op it executed.
    final applied = await ComponentIpcBridge.startLauncher(cmd: extras['cmd']);
    if (applied != null) {
      await DvmaEvidence.record(
        IntentArgInjectionRceScreen.vulnId,
        'exported-handler-executed-arg',
        'exported handler executed injected arg for external caller: $applied',
      );
    }

    setState(() {
      _vulnResult =
          'op: ${vuln.op}\n'
          'executed: ${vuln.executed}\n'
          '${vuln.output}';
      _secureResult =
          'op: ${secure.op}\n'
          'executed: ${secure.executed}\n'
          '${secure.output}';
      _nativeApplied = applied;
    });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: IntentArgInjectionRceScreen.vulnId,
      title: 'Intent Argument Injection -> Local Code Execution',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'An exported "launcher" component reads attacker-controlled intent '
          'extras (cmd=..., loadLibrary=..., -xrun/path) and feeds them '
          'straight into an execution path. A malicious app can therefore send '
          'an intent that selects a privileged op - dumping app secrets or '
          '"loading" an attacker-supplied library path - which runs with THIS '
          'app\'s privileges (the Unity CVE-2025-59489 class). This is an '
          'offline, deterministic simulation: the Intent is a Map of extras and '
          'the executor maps op strings to effects. A secure handler allowlists '
          'only safe navigation actions and ignores any injected execution arg.',
      children: [
        Padding(
          padding: const EdgeInsets.only(top: DvmaSpacing.md),
          child: TextField(
            controller: _controller,
            decoration: const InputDecoration(
              labelText: 'attacker intent extra',
              hintText: 'cmd=dump_secrets or -xrun/data/local/tmp/evil.so',
              border: OutlineInputBorder(),
            ),
          ),
        ),
        DemoActionButton(
          label: 'Deliver intent (exported)',
          onPressed: _deliver,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'exported handler (attacker arg executes)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'allowlisted handler (injection rejected)',
            value: _secureResult!,
          ),
        if (_nativeApplied != null)
          EvidencePanel(
            label: 'real exported LauncherActivity executed injected arg',
            value: _nativeApplied!,
          ),
      ],
    );
  }
}
