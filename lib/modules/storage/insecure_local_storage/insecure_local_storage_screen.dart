import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'insecure_storage.dart';

/// Insecure Local Storage (Plaintext SharedPreferences/UserDefaults).
///
/// Auth token and PII written to SharedPreferences/UserDefaults in cleartext.
class InsecureLocalStorageScreen extends StatefulWidget {
  const InsecureLocalStorageScreen({super.key});

  static const String vulnId = 'insecure_local_storage';

  @override
  State<InsecureLocalStorageScreen> createState() =>
      _InsecureLocalStorageScreenState();
}

class _InsecureLocalStorageScreenState
    extends State<InsecureLocalStorageScreen> {
  final _token = TextEditingController(text: 'eyJhbGciOiJIUzI1NiJ9.session');
  final _ssn = TextEditingController(text: '123-45-6789');
  final _card = TextEditingController(text: '4111 1111 1111 1111');
  Map<String, String?> _stored = {};
  bool _sending = false;

  Future<void> _save() async {
    setState(() => _sending = true);
    final lingo = PlatformLingo.current();

    final prefs = await SharedPreferences.getInstance();
    final storage = InsecureStorage(prefs);
    // VULN (unchanged): real cleartext write to the local key-value store.
    await storage.saveSensitive(
      token: _token.text,
      ssn: _ssn.text,
      creditCard: _card.text,
    );
    final stored = storage.dumpRaw();

    // The real leak is the on-disk backing file. Mirror the exact stored
    // key=value lines and the backing path to the evidence sink so the harness
    // (adb / a backup) can find and pull it.
    final artifact =
        '${stored.entries.map((e) => '${e.key}=${e.value}').join('\n')}'
        '\n\nbacking file ${lingo.backingReadableParenthetical}: '
        '${lingo.keyValueBackingPath}';
    await DvmaEvidence.record(
      InsecureLocalStorageScreen.vulnId,
      'prefs',
      artifact,
    );

    if (!mounted) return;
    setState(() {
      _sending = false;
      _stored = stored;
    });
  }

  @override
  Widget build(BuildContext context) {
    final lingo = PlatformLingo.current();
    return VulnDemoScaffold(
      vulnId: InsecureLocalStorageScreen.vulnId,
      title: 'Insecure Local Storage',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'Sensitive values are written to SharedPreferences (Android) / '
          'NSUserDefaults (iOS) as cleartext. On a rooted/jailbroken device or '
          'via ${lingo.pullTool}, the backing ${lingo.keyValueBackingFile} '
          'exposes everything.',
      children: [
        TextField(
          controller: _token,
          decoration: const InputDecoration(labelText: 'Auth token'),
        ),
        const SizedBox(height: DvmaSpacing.sm),
        TextField(
          controller: _ssn,
          decoration: const InputDecoration(labelText: 'SSN'),
        ),
        const SizedBox(height: DvmaSpacing.sm),
        TextField(
          controller: _card,
          decoration: const InputDecoration(labelText: 'Credit card'),
        ),
        DemoActionButton(
          label: _sending ? 'Storing…' : 'Store insecurely',
          onPressed: _sending ? () {} : () => _save(),
        ),
        if (_stored.isNotEmpty)
          EvidencePanel(
            label: 'stored as cleartext (${lingo.keyValueStore})',
            value: _stored.entries
                .map((e) => '${e.key} = ${e.value}')
                .join('\n'),
          ),
      ],
    );
  }
}
