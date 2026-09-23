import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show MissingPluginException;
import 'package:shared_preferences/shared_preferences.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'credential_manager.dart';

/// Insecure Credential Manager / Autofill Integration.
///
/// Associates credentials with an unverified domain (no Digital Asset Links /
/// AASA check) and autofills secrets into an insecure/plaintext field.
class InsecureCredentialManagerScreen extends StatefulWidget {
  const InsecureCredentialManagerScreen({super.key});

  static const String vulnId = 'insecure_credential_manager';

  @override
  State<InsecureCredentialManagerScreen> createState() =>
      _InsecureCredentialManagerScreenState();
}

class _InsecureCredentialManagerScreenState
    extends State<InsecureCredentialManagerScreen> {
  final _manager = InsecureCredentialManager();
  final _domain = TextEditingController(text: 'dvma-training.attacker.com');
  // An intentionally insecure autofill target: plaintext, no obscureText.
  final _autofillField = TextEditingController();

  String? _associateResult;
  String? _autofillResult;

  Future<void> _associate() async {
    const username = 'victim@dvma.training';
    const password = 'S3cretP@ss';
    _manager.associate(
      domain: _domain.text,
      username: username,
      password: password,
    );
    final verified = InsecureCredentialManager.verifiedDomains.contains(
      _domain.text,
    );
    // real side effect: persist the credential associated with the UNVERIFIED
    // (phishing look-alike) domain to real SharedPreferences as cleartext.
    const prefsKey = 'dvma_credential_manager';
    final stored =
        'domain=${_domain.text} verified=$verified '
        'username=$username password=$password';
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(prefsKey, stored);
    } on MissingPluginException {
      // No platform channel in unit tests; evidence line below still emits.
    } catch (_) {}
    await DvmaEvidence.record(
      InsecureCredentialManagerScreen.vulnId,
      'credential',
      'shared_prefs key=$prefsKey :: $stored',
    );
    if (!mounted) return;
    setState(
      () => _associateResult =
          'associated credential with "${_domain.text}"\n'
          'domain verified via asset-links/AASA: $verified\n'
          'secure manager would associate: '
          '${_manager.secureWouldAssociate(_domain.text)}',
    );
  }

  void _autofill() {
    // fieldSecure:false -> plaintext field, keyboard-cacheable.
    final cred = _manager.autofill(domain: _domain.text, fieldSecure: false);
    if (cred != null) {
      _autofillField.text = cred.password;
    }
    setState(
      () => _autofillResult = cred == null
          ? 'no credential for domain'
          : 'autofilled ${cred.username} / ${cred.password} '
                'into an INSECURE (plaintext) field',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: InsecureCredentialManagerScreen.vulnId,
      title: 'Insecure Credential Manager',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The app associates saved credentials with any requested domain '
          'without verifying the Digital Asset Links (Android) / AASA (iOS) '
          'association, so a phishing look-alike domain is trusted like the '
          'real one. It then autofills the secret into a plaintext, '
          'keyboard-cacheable field. A secure integration only associates with '
          'cryptographically-verified domains and requires secure fields.',
      children: [
        TextField(
          controller: _domain,
          decoration: const InputDecoration(
            labelText: 'Requesting domain (unverified)',
          ),
        ),
        DemoActionButton(
          label: 'Associate credential with domain',
          onPressed: _associate,
        ),
        if (_associateResult != null)
          EvidencePanel(
            label: 'association decision',
            value: _associateResult!,
          ),
        DemoActionButton(label: 'Autofill into field', onPressed: _autofill),
        TextField(
          controller: _autofillField,
          // VULN: not obscured, autocorrect/caching enabled - insecure target.
          decoration: const InputDecoration(
            labelText: 'password (insecure autofill target)',
          ),
        ),
        if (_autofillResult != null)
          EvidencePanel(label: 'autofill result', value: _autofillResult!),
      ],
    );
  }
}
