import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/system_provider_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'ime_keyboard.dart';

/// Custom Keyboard Input Interception.
///
/// A custom keyboard / InputMethodService captures sensitive input typed in
/// other apps and exfiltrates it because it has network access and lacks
/// isolation.
class CustomKeyboardInputInterceptionScreen extends StatefulWidget {
  const CustomKeyboardInputInterceptionScreen({super.key});

  static const String vulnId = 'custom_keyboard_input_interception';

  @override
  State<CustomKeyboardInputInterceptionScreen> createState() =>
      _CustomKeyboardInputInterceptionScreenState();
}

class _CustomKeyboardInputInterceptionScreenState
    extends State<CustomKeyboardInputInterceptionScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeFinding;

  String _render(InterceptionResult r, {required bool network}) {
    final b = StringBuffer();
    b.writeln('editing field      : ${r.field.name}');
    b.writeln('secure field       : ${r.field.secureField}');
    b.writeln('network access     : $network');
    b.writeln(
      'captured (keylog)  : ${r.captured.isEmpty ? '(none)' : r.captured}',
    );
    b.writeln(
      'exfiltrated        : ${r.exfiltrated.isEmpty ? '(none)' : r.exfiltrated}',
    );
    if (r.exfiltrated.isNotEmpty) {
      b.writeln('exfil endpoint     : ${ImeKeyboard.exfilEndpoint}');
    }
    b.writeln('sensitive leaked   : ${r.sensitiveLeaked}');
    if (r.note != null) {
      b.writeln('note               : ${r.note}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // real native probe: read Settings.Secure enabled_input_methods and report
    // whether DVMA's own custom IME (declared in the manifest as
    // DvmaKeyboardService) is currently enabled/selected, the true grant state
    // for a keystroke-intercepting keyboard.
    final native = await SystemProviderBridge.enabledProviders();

    // VULN: a network-enabled keyboard captures + exfiltrates the password.
    final vulnKb = ImeKeyboard(hasNetworkAccess: true);
    final vuln = vulnKb.onKey(ImeKeyboard.passwordField, ImeKeyboard.secret);

    // SECURE: an isolated keyboard refuses to log/transmit secure fields.
    final secureKb = ImeKeyboard(hasNetworkAccess: false);
    final secure = secureKb.onKeySafe(
      ImeKeyboard.passwordField,
      ImeKeyboard.secret,
    );

    await DvmaEvidence.record(
      CustomKeyboardInputInterceptionScreen.vulnId,
      'keyboard-interception',
      'enabledInputMethods=${native ?? 'unavailable (off-Android fallback)'} :: '
          'capturedSecret=${vuln.captured} :: '
          'exfilEndpoint=${ImeKeyboard.exfilEndpoint}',
    );

    if (!mounted) return;
    setState(() {
      _nativeFinding = native ?? 'native unavailable (off-Android fallback)';
      _vulnResult = _render(vuln, network: true);
      _secureResult = _render(secure, network: false);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: CustomKeyboardInputInterceptionScreen.vulnId,
      title: 'Custom Keyboard Input Interception',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'A custom keyboard / InputMethodService (or iOS keyboard extension) '
          'sees EVERY keystroke the user types across other apps - including '
          'passwords and OTPs in secure fields. Granted "Allow Full Access" '
          '(network egress) and running without isolation, it logs and '
          'exfiltrates that input to an attacker sink. This is an offline, '
          'deterministic simulation - the endpoint is never actually '
          'contacted. The secure path refuses to log/transmit for secure '
          'fields and runs with no network access. DVMA now declares a REAL, '
          'user-enablable custom keyboard (DvmaKeyboardService); the "real '
          'state" panel reports whether it is enabled via Settings.Secure. To '
          'fully arm it, enable "DVMA Training Keyboard" under Settings > '
          'Languages & input > On-screen keyboards and select it - it then '
          'sees keystrokes typed in other apps (watch logcat DVMA-EVIDENCE).',
      children: [
        DemoActionButton(label: 'Type password into keyboard', onPressed: _run),
        if (_nativeFinding != null)
          EvidencePanel(
            label: 'real enabled-IME state (native)',
            value: _nativeFinding!,
          ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'captured-keystrokes evidence (exfiltrated)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'secure field not logged / isolated keyboard',
            value: _secureResult!,
          ),
      ],
    );
  }
}
