import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'untrusted_module_loader.dart';

/// Dynamic Code Loading (Arbitrary Code Execution).
///
/// Loads and executes a dex/module/plugin from an untrusted third-party app or
/// external storage with no verification.
class DynamicCodeLoadingRceScreen extends StatefulWidget {
  const DynamicCodeLoadingRceScreen({super.key});

  static const String vulnId = 'dynamic_code_loading_rce';

  @override
  State<DynamicCodeLoadingRceScreen> createState() =>
      _DynamicCodeLoadingRceScreenState();
}

class _DynamicCodeLoadingRceScreenState
    extends State<DynamicCodeLoadingRceScreen> {
  final _module = TextEditingController(text: 'wipe_data');
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  Future<void> _run() async {
    final name = _module.text;
    final vuln = UntrustedModuleLoader.loadAndRun(name);
    final secure = UntrustedModuleLoader.secureLoadAndRun(name);
    setState(() {
      _vulnResult = 'executed: ${vuln.executed}\noutput: ${vuln.output}';
      _secureResult = 'executed: ${secure.executed}\noutput: ${secure.output}';
    });

    // On Android, DexClassLoader over an app-writable file then reflectively
    // invoke the loaded (unverified) code, reading back the native evidence.
    final native = await PlatformIpcBridge.dynamicCodeLoad();
    if (native == null || native.isEmpty) return;
    await DvmaEvidence.record(
      DynamicCodeLoadingRceScreen.vulnId,
      'dynamic-code-load',
      'real DexClassLoader over app-writable file executed:\n$native',
    );
    if (!mounted) return;
    setState(() => _nativeResult = native);
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: DynamicCodeLoadingRceScreen.vulnId,
      title: 'Dynamic Code Loading (RCE)',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A plugin loader maps an untrusted module name to an executable op '
          'and runs it with no signature or allowlist check, so an '
          'attacker-supplied "wipe_data" module executes inside the app. This '
          'is a Dart simulation; the real exploit is native (DexClassLoader / '
          'dlopen loading an unsigned .dex/.so from an untrusted origin). A '
          'secure loader only runs allowlisted, signed modules.',
      children: [
        TextField(
          controller: _module,
          decoration: const InputDecoration(labelText: 'Untrusted module name'),
        ),
        DemoActionButton(label: 'Load & run module', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(label: 'vulnerable loader', value: _vulnResult!),
        if (_secureResult != null)
          EvidencePanel(
            label: 'allowlist + signature loader',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real DexClassLoader executed unverified code',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
