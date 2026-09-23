import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Keyboard Cache & Autofill Leakage.
///
/// Sensitive text fields allow keyboard caching / autofill of secrets.
class KeyboardCacheAutofillLeakageScreen extends StatefulWidget {
  const KeyboardCacheAutofillLeakageScreen({super.key});

  static const String vulnId = 'keyboard_cache_autofill_leakage';

  @override
  State<KeyboardCacheAutofillLeakageScreen> createState() =>
      _KeyboardCacheAutofillLeakageScreenState();
}

class _KeyboardCacheAutofillLeakageScreenState
    extends State<KeyboardCacheAutofillLeakageScreen> {
  final _seed = TextEditingController(text: 'correct horse battery staple');

  // real artifact: the actual configuration of the field below. A secure secret
  // field would flip all three; this one leaves the keyboard free to learn what
  // is typed and lets the OS capture it into the recents thumbnail.
  static const bool autocorrect = true;
  static const bool enableSuggestions = true;
  static const bool obscureText = false;

  String? _config;
  String? _nativeState;
  bool _running = false;

  Future<void> _run() async {
    if (_running) return;
    setState(() => _running = true);

    // Truthful facts about the field (no fabricated dictionary entries): with
    // autocorrect/suggestions on and obscureText off, whatever is typed is
    // eligible for the keyboard/autofill cache and for the recents thumbnail.
    final config =
        'autocorrect        = $autocorrect\n'
        'enableSuggestions  = $enableSuggestions\n'
        'obscureText        = $obscureText\n'
        '=> typed text is eligible for the keyboard/autofill cache and the '
        'recents snapshot';

    await DvmaEvidence.record(
      KeyboardCacheAutofillLeakageScreen.vulnId,
      'keyboard-cache',
      'unprotected field config: autocorrect=$autocorrect, '
          'enableSuggestions=$enableSuggestions, obscureText=$obscureText -> '
          'typed text eligible for keyboard/autofill cache + recents snapshot',
    );

    // On Android, read the real window FLAG_SECURE / recents-screenshot posture
    // of DVMA's own window: an unset FLAG_SECURE means this field (and its
    // typed content) is screenshot-eligible / captured into the recents
    // thumbnail (device-observable via the native probe / a recents screenshot).
    final native = await PlatformIpcBridge.flagSecureState();
    if (native != null) {
      await DvmaEvidence.record(
        KeyboardCacheAutofillLeakageScreen.vulnId,
        'keyboard-cache-native',
        'real window posture (screenshot-eligible): $native',
      );
    }

    if (!mounted) return;
    setState(() {
      _config = config;
      _nativeState = native;
      _running = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: KeyboardCacheAutofillLeakageScreen.vulnId,
      title: 'Keyboard Cache & Autofill Leakage',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'This secret field leaves autocorrect and suggestions ON and is not '
          'obscured, so what the user types is eligible to be learned by the '
          'keyboard (personal dictionary / next-word model, later autofilled in '
          'other apps) and, because the window is not FLAG_SECURE, captured '
          'into the recents thumbnail. The misconfigured field below is the real '
          'artifact; the probe reports only the field\'s actual configuration '
          'flags and the real window screenshot posture - not invented '
          'dictionary entries. A secure field would set obscureText:true, '
          'autocorrect:false, enableSuggestions:false.',
      children: [
        TextField(
          controller: _seed,
          // The insecure configuration (real artifact):
          autocorrect: autocorrect,
          enableSuggestions: enableSuggestions,
          obscureText: obscureText,
          keyboardType: TextInputType.text,
          decoration: const InputDecoration(
            labelText: 'Recovery phrase (unprotected field)',
          ),
        ),
        DemoActionButton(
          label: _running ? 'Checking...' : 'Check field cache exposure',
          onPressed: _running ? () {} : _run,
        ),
        if (_config != null)
          EvidencePanel(
            label: 'field is cache/snapshot eligible (actual config)',
            value: _config!,
          ),
        if (_nativeState != null)
          EvidencePanel(
            label: 'real window screenshot posture (device-observable)',
            value: _nativeState!,
          ),
        const EvidencePanel(
          label: 'secure field contrast',
          value:
              'obscureText = true\nautocorrect = false\n'
              'enableSuggestions = false',
        ),
      ],
    );
  }
}
