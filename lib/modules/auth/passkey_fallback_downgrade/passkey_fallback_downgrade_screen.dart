import 'package:flutter/material.dart';

import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../passkey_ceremony.dart';
import 'passkey_fallback_flow.dart';

/// Passkey Fallback / Downgrade Attack.
///
/// Passkey auth silently falls back to a weak password/OTP path an attacker
/// can force (authentication downgrade).
class PasskeyFallbackDowngradeScreen extends StatefulWidget {
  const PasskeyFallbackDowngradeScreen({super.key});

  static const String vulnId = 'passkey_fallback_downgrade';

  @override
  State<PasskeyFallbackDowngradeScreen> createState() =>
      _PasskeyFallbackDowngradeScreenState();
}

class _PasskeyFallbackDowngradeScreenState
    extends State<PasskeyFallbackDowngradeScreen> {
  bool _forceUnavailable = true;
  final _password = TextEditingController(
    text: PasskeyFallbackFlow.fallbackPassword,
  );
  String? _result;
  String? _prefsKey;

  Future<void> _run() async {
    // Attacker signals "passkeys unavailable" to force the weak fallback path.
    final result = PasskeyFallbackFlow.login(
      passkeyAvailable: !_forceUnavailable,
      passkeyAssertionValid: true,
      fallbackAttempt: _password.text,
    );

    String? prefsKey;
    // VULN: when login succeeds via the downgraded password fallback, persist
    // that success to real SharedPreferences. The recoverable artifact records
    // a phishing-resistant passkey account authenticated by a weak password.
    if (result.success && result.downgraded) {
      prefsKey = await PasskeyEvidenceStore.persist(
        vulnId: PasskeyFallbackDowngradeScreen.vulnId,
        kind: 'fallback-downgrade',
        keySuffix: 'downgraded_login',
        value:
            'method=${result.method} success=${result.success} '
            'password=${_password.text}',
      );
    }
    if (!mounted) return;

    setState(() {
      _prefsKey = prefsKey;
      _result =
          'success=${result.success} '
          'method=${result.method} '
          'downgraded=${result.downgraded}';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PasskeyFallbackDowngradeScreen.vulnId,
      title: 'Passkey Fallback Downgrade',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The login flow silently downgrades to a weak password fallback when '
          'passkeys appear unavailable - and an attacker can force that by '
          'signalling "no passkey", defeating the phishing resistance passkeys '
          'provide. No step-up or risk check gates the downgrade.'
          ' ${PasskeyCeremony.scopeNote}',
      children: [
        SwitchListTile(
          value: _forceUnavailable,
          onChanged: (v) => setState(() => _forceUnavailable = v),
          title: const Text('Attacker forces "passkey unavailable"'),
          contentPadding: EdgeInsets.zero,
        ),
        TextField(
          controller: _password,
          decoration: const InputDecoration(labelText: 'Fallback password'),
        ),
        DemoActionButton(label: 'Attempt login', onPressed: _run),
        if (_result != null)
          EvidencePanel(label: 'login result', value: _result!),
        if (_prefsKey != null)
          DeviceArtifactPanel(
            storeKey: _prefsKey!,
            describes: 'the downgraded password-fallback login success',
          ),
      ],
    );
  }
}
