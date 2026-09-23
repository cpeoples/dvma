import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Insecure / Bypassable Biometric Prompt.
///
/// Local auth is event-bound UI only; failure path is trivially bypassed.
class InsecureBiometricPromptScreen extends StatefulWidget {
  const InsecureBiometricPromptScreen({super.key});

  static const String vulnId = 'insecure_biometric_prompt';

  @override
  State<InsecureBiometricPromptScreen> createState() =>
      _InsecureBiometricPromptScreenState();
}

class _InsecureBiometricPromptScreenState
    extends State<InsecureBiometricPromptScreen> {
  bool _unlocked = false;
  String? _note;

  // VULN: the "secret" is already decrypted/available client-side; the biometric
  // prompt is a pure UI gate that just flips a boolean. Nothing is bound to the
  // biometric result (no Keystore key requiring auth), so hooking the callback
  // or patching the boolean unlocks it.
  static const String _protectedSecret = 'DVMA{biometric_ui_only}';

  void _authenticate({required bool success}) {
    // Even the "failure" path here can be flipped to success by an attacker
    // (frida/objection) because the decision is a client-side boolean.
    if (success) {
      // Real leak: the "protected" secret is released purely on a client-side
      // boolean, so the bypass exposes it with nothing bound to biometrics.
      DvmaEvidence.record(
        InsecureBiometricPromptScreen.vulnId,
        'biometric-bypass',
        'unlocked secret via client-side boolean (no Keystore binding): '
            '$_protectedSecret',
      );
    }
    setState(() {
      _unlocked = success;
      _note = success
          ? 'onAuthSuccess() called -> unlocked'
          : 'onAuthError() -> but attacker can call onAuthSuccess() directly';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: InsecureBiometricPromptScreen.vulnId,
      title: 'Insecure / Bypassable Biometric Prompt',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The biometric prompt is decorative: success/failure just flips a '
          'client-side boolean and the protected secret is already in memory. '
          'Nothing is cryptographically bound to a Keystore/Keychain key that '
          'requires user authentication, so a frida hook (or patching the '
          'boolean) unlocks it. The buttons simulate the auth callbacks.',
      children: [
        Row(
          children: [
            Expanded(
              child: DemoActionButton(
                label: 'Biometric success',
                onPressed: () => _authenticate(success: true),
              ),
            ),
            const SizedBox(width: DvmaSpacing.sm),
            Expanded(
              child: DemoActionButton(
                label: 'Bypass (call success on fail)',
                onPressed: () => _authenticate(success: true),
              ),
            ),
          ],
        ),
        if (_note != null) EvidencePanel(label: 'auth path', value: _note!),
        if (_unlocked)
          EvidencePanel(label: 'unlocked secret', value: _protectedSecret),
      ],
    );
  }
}
