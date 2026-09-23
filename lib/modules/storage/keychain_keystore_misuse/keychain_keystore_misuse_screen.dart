import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'keychain_store.dart';

/// Keychain/Keystore Misuse.
///
/// Secrets stored without hardware-backed protection / with weak accessibility
/// flags.
class KeychainKeystoreMisuseScreen extends StatefulWidget {
  const KeychainKeystoreMisuseScreen({super.key});

  static const String vulnId = 'keychain_keystore_misuse';

  @override
  State<KeychainKeystoreMisuseScreen> createState() =>
      _KeychainKeystoreMisuseScreenState();
}

class _KeychainKeystoreMisuseScreenState
    extends State<KeychainKeystoreMisuseScreen> {
  final _store = KeychainStore();
  final _secret = TextEditingController(text: 'refresh_token=DVMA{keychain}');
  Map<String, String> _dump = {};
  bool _saving = false;

  Future<void> _save() async {
    setState(() => _saving = true);
    final lingo = PlatformLingo.current();

    // VULN: write the "secret" into the platform store with the weakest
    // accessibility class. On device this lands in the local key-value store
    // in cleartext (recoverable off-device), the real keychain-misuse leak.
    await _store.store('refresh_token', _secret.text);
    final dump = await _store.dumpAll();

    // Mirror the real artifact (the stored key=value plus the weak protection
    // flags and the recoverable backing file) to the evidence sink.
    final artifact =
        '${dump.entries.map((e) => '${KeychainStore.prefsKey(e.key)}=${e.value}').join('\n')}'
        '\n\naccessibility = ${KeychainStore.accessibility}'
        '\nrequiresUserAuthentication = ${KeychainStore.requiresUserAuthentication}'
        '\nhardwareBacked = ${KeychainStore.hardwareBacked}'
        '\n\nbacking file ${lingo.backingReadableParenthetical}: '
        '${lingo.keyValueBackingPath}';
    // Fire-and-forget: evidence capture must not perturb the vulnerable path.
    DvmaEvidence.record(
      KeychainKeystoreMisuseScreen.vulnId,
      'keystore',
      artifact,
    );

    if (!mounted) return;
    setState(() {
      _saving = false;
      _dump = dump;
    });
  }

  @override
  Widget build(BuildContext context) {
    final lingo = PlatformLingo.current();
    return VulnDemoScaffold(
      vulnId: KeychainKeystoreMisuseScreen.vulnId,
      title: 'Keychain/Keystore Misuse',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The secret is stored in the platform secret store with the weakest '
          'accessibility class (kSecAttrAccessibleAlways / no user-auth, no '
          'hardware backing). On device the value lands in the '
          '${lingo.keyValueStore} in cleartext, so it is readable while the '
          'device is locked, is copied into backups, and is recoverable via '
          '${lingo.pullTool}. The stronger exploit is platform-level '
          '(keychain-dumper / frida); the weak flags and the missing auth gate '
          'are faithful.',
      children: [
        TextField(
          controller: _secret,
          decoration: const InputDecoration(labelText: 'Secret to store'),
        ),
        DemoActionButton(
          label: _saving ? 'Storing…' : 'Store in "keychain"',
          onPressed: _saving ? () {} : () => _save(),
        ),
        EvidencePanel(
          label: 'protection flags',
          value:
              'accessibility = ${KeychainStore.accessibility}\n'
              'requiresUserAuthentication = '
              '${KeychainStore.requiresUserAuthentication}\n'
              'hardwareBacked = ${KeychainStore.hardwareBacked}',
        ),
        if (_dump.isNotEmpty)
          EvidencePanel(
            label: 'dumped items (no auth required)',
            value: _dump.entries.map((e) => '${e.key} = ${e.value}').join('\n'),
          ),
      ],
    );
  }
}
