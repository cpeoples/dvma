import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../passkey_ceremony.dart';
import 'passkey_credential_store.dart';

/// Passkey Credential Exfiltration.
///
/// Passkey/credential material is cached in app-private storage without
/// hardware-backed protection, allowing extraction.
class PasskeyCredentialExfiltrationScreen extends StatefulWidget {
  const PasskeyCredentialExfiltrationScreen({super.key});

  static const String vulnId = 'passkey_credential_exfiltration';

  @override
  State<PasskeyCredentialExfiltrationScreen> createState() =>
      _PasskeyCredentialExfiltrationScreenState();
}

class _PasskeyCredentialExfiltrationScreenState
    extends State<PasskeyCredentialExfiltrationScreen> {
  String? _exfiltrated;

  Future<void> _run() async {
    final prefs = await SharedPreferences.getInstance();
    final store = PasskeyCredentialStore(prefs);
    await store.cacheCredential(
      credentialId: 'cred-abc123',
      rpId: 'dvma.training',
      // A stand-in "private key" that should never leave secure hardware.
      privateKeyBytes: List<int>.generate(32, (i) => (i * 7) & 0xff),
    );
    setState(() => _exfiltrated = store.exfiltrate());
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PasskeyCredentialExfiltrationScreen.vulnId,
      title: 'Passkey Credential Exfiltration',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'Passkey private-key material must stay in hardware-backed storage '
          '(Keystore StrongBox / Secure Enclave) and be non-exportable. Here '
          'the app caches the private key in cleartext SharedPreferences, so it '
          'can be pulled off-device with adb/objection and the passkey cloned.'
          ' ${PasskeyCeremony.scopeNote}',
      children: [
        DemoActionButton(
          label: 'Register & cache passkey (insecurely)',
          onPressed: _run,
        ),
        if (_exfiltrated != null)
          EvidencePanel(
            label: 'exfiltrated credential blob (cleartext)',
            value: _exfiltrated!,
          ),
      ],
    );
  }
}
