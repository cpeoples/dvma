import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Clipboard Leakage of Sensitive Fields.
///
/// Copies passwords/tokens to the global clipboard readable by any app.
class ClipboardLeakageScreen extends StatefulWidget {
  const ClipboardLeakageScreen({super.key});

  static const String vulnId = 'clipboard_leakage';

  @override
  State<ClipboardLeakageScreen> createState() => _ClipboardLeakageScreenState();
}

class _ClipboardLeakageScreenState extends State<ClipboardLeakageScreen> {
  final _secret = TextEditingController(text: 'DVMA{clipboard_secret}');
  String? _copied;

  Future<void> _copy() async {
    // Writes the secret to the GLOBAL system clipboard with no
    // "sensitive"/no-history hint. Any other app (or clipboard-history UI) can
    // read it. Guarded so it still builds in a test harness without a plugin.
    try {
      await Clipboard.setData(ClipboardData(text: _secret.text));
    } on MissingPluginException {
      // No platform clipboard in the test harness; the vulnerable call path
      // (Clipboard.setData with no protection) is what matters.
    }
    // Real leak: the secret was placed on the global clipboard (any app can
    // read it). Mirror the copied value.
    DvmaEvidence.record(
      ClipboardLeakageScreen.vulnId,
      'clipboard',
      'copied to global clipboard (readable by any app): ${_secret.text}',
    );
    setState(() => _copied = _secret.text);
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ClipboardLeakageScreen.vulnId,
      title: 'Clipboard Leakage',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'The password/token is copied to the shared system clipboard with no '
          'sensitivity flag and no auto-clear. On Android any app can read the '
          'clipboard (pre-10) or it appears in clipboard history; iOS exposes '
          'it to the universal pasteboard. Secrets should never touch the '
          'global clipboard.',
      children: [
        TextField(
          controller: _secret,
          decoration: const InputDecoration(labelText: 'Secret / password'),
        ),
        DemoActionButton(label: 'Copy to clipboard', onPressed: _copy),
        if (_copied != null)
          EvidencePanel(
            label: 'now on global clipboard (any app can read)',
            value: _copied!,
          ),
      ],
    );
  }
}
