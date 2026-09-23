import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// No Obfuscation / Symbol Stripping.
///
/// Ships with readable symbols; no ProGuard/R8/Dart obfuscation.
class NoObfuscationScreen extends StatefulWidget {
  const NoObfuscationScreen({super.key});

  static const String vulnId = 'no_obfuscation';

  @override
  State<NoObfuscationScreen> createState() => _NoObfuscationScreenState();
}

class _NoObfuscationScreenState extends State<NoObfuscationScreen> {
  // A representative slice of the readable symbols left in the binary because
  // no R8/ProGuard/--obfuscate was applied.
  static const List<String> _symbols = [
    'com.dvma.auth.LoginManager.validateCredentials(String,String)',
    'com.dvma.crypto.KeyVault.getMasterKey() -> "DVMA{unobfuscated}"',
    'com.dvma.net.ApiClient.BASE_URL = "https://api.dvma.example"',
    'com.dvma.flags.FeatureFlags.isAdminUnlocked',
  ];

  String? _strings;

  Future<void> _run() async {
    final strings = _symbols.map((s) => 'strings> $s').join('\n');
    // real artifact: capture live proof that Dart symbols are not obfuscated -
    // this State's readable runtimeType and a captured stack trace still carry
    // human-readable class/method names (they would be mangled under
    // --obfuscate). This is genuinely extracted at runtime from this build.
    final runtimeSymbol = runtimeType.toString();
    String stack;
    try {
      throw StateError('no-obfuscation probe');
    } catch (_, st) {
      stack = st.toString();
    }
    final unobfuscated =
        !runtimeSymbol.startsWith('_') ||
        runtimeSymbol.contains('NoObfuscation');
    await DvmaEvidence.record(
      NoObfuscationScreen.vulnId,
      'symbols',
      'readable Dart symbols present (no --obfuscate): '
          'runtimeType=$runtimeSymbol symbolsReadable=$unobfuscated :: '
          'stack head=${stack.split('\n').take(3).join(' | ')} :: '
          'recovered=${_symbols.join(" ; ")}',
    );
    if (!mounted) return;
    setState(() => _strings = strings);
  }

  @override
  Widget build(BuildContext context) {
    final lingo = PlatformLingo.current();
    return VulnDemoScaffold(
      vulnId: NoObfuscationScreen.vulnId,
      title: 'No Obfuscation / Symbol Stripping',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'The build applies no obfuscation (no R8/ProGuard on Android or '
          'symbol stripping on iOS, no Flutter --obfuscate), so class/method '
          'names, URLs, and even key material are readable with '
          '${lingo.reverseTools} - making reverse engineering trivial. '
          'This is a build-config property; the sample shows recoverable '
          'symbols.',
      children: [
        DemoActionButton(
          label: 'Run strings on the ${lingo.appArtifact}',
          onPressed: _run,
        ),
        if (_strings != null)
          EvidencePanel(
            label: 'recovered symbols (readable)',
            value: _strings!,
          ),
      ],
    );
  }
}
