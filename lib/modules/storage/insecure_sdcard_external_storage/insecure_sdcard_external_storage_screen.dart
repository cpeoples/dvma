import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'external_storage_leak.dart';

/// Insecure SD-Card / External Storage.
///
/// Writes sensitive files to shared/external storage where any app with storage
/// access can read them.
class InsecureSdcardExternalStorageScreen extends StatefulWidget {
  const InsecureSdcardExternalStorageScreen({super.key});

  static const String vulnId = 'insecure_sdcard_external_storage';

  @override
  State<InsecureSdcardExternalStorageScreen> createState() =>
      _InsecureSdcardExternalStorageScreenState();
}

class _InsecureSdcardExternalStorageScreenState
    extends State<InsecureSdcardExternalStorageScreen> {
  final _secret = TextEditingController(
    text: 'auth_token=eyJhbGciOiJIUzI1NiJ9.session\nssn=123-45-6789',
  );
  String? _path;
  String? _readBack;
  bool _sending = false;

  Future<void> _run() async {
    setState(() {
      _sending = true;
      _path = null;
      _readBack = null;
    });

    // VULN: writes the secret as a cleartext file into shared / external
    // storage (Android external files dir, adb-pullable). On a real device
    // external storage is world-readable to any app with storage access, so
    // the file leaks the moment it is written.
    final path = await ExternalStorageLeak.writeSensitiveFile(_secret.text);
    final readBack = await ExternalStorageLeak.readAsOtherApp(path);

    await DvmaEvidence.record(
      InsecureSdcardExternalStorageScreen.vulnId,
      'sdcard-file',
      'wrote world-readable file at $path\n\n$readBack',
    );

    if (!mounted) return;
    setState(() {
      _sending = false;
      _path = path;
      _readBack = readBack;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: InsecureSdcardExternalStorageScreen.vulnId,
      title: 'Insecure External Storage',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'The secret is written as a cleartext file into shared / external '
          'storage. On a real device, external storage is world-readable to any '
          'app with storage access (and to adb / any file-manager app), so the '
          'file below leaks the moment it is written. This writes a file - '
          'on Android into the external files dir, elsewhere into app '
          'documents. Sensitive data must stay in app-private, encrypted '
          'storage.',
      children: [
        TextField(
          controller: _secret,
          maxLines: 2,
          decoration: const InputDecoration(labelText: 'Sensitive contents'),
        ),
        DemoActionButton(
          label: _sending ? 'Writing…' : 'Write to external storage',
          onPressed: _sending ? () {} : () => _run(),
        ),
        if (_path != null)
          EvidencePanel(label: 'world-readable file path', value: _path!),
        if (_readBack != null)
          EvidencePanel(
            label: 'read back by "another app" (cleartext)',
            value: _readBack!,
          ),
      ],
    );
  }
}
