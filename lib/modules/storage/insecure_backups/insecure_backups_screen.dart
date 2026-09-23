import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'insecure_backup_writer.dart';

/// Insecure Backups (allowBackup / unencrypted iOS backups).
///
/// android:allowBackup=true and no iOS backup exclusion leak app data to
/// backups.
class InsecureBackupsScreen extends StatefulWidget {
  const InsecureBackupsScreen({super.key});

  static const String vulnId = 'insecure_backups';

  @override
  State<InsecureBackupsScreen> createState() => _InsecureBackupsScreenState();
}

class _InsecureBackupsScreenState extends State<InsecureBackupsScreen> {
  // Insecure manifest settings (mirrors AndroidManifest.xml / Info.plist).
  static const bool allowBackup = true; // android:allowBackup
  static const bool fullBackupContent = false; // no include/exclude rules
  static const bool iosExcludedFromBackup =
      false; // no NSURLIsExcludedFromBackup

  String? _path;
  String? _contents;
  bool _sending = false;

  Future<void> _runBackup() async {
    setState(() {
      _sending = true;
      _path = null;
      _contents = null;
    });

    // VULN: with allowBackup=true and no exclusions, this cleartext blob
    // of tokens/PII, written into the app sandbox, is captured verbatim by an
    // unauthenticated `adb backup` / iTunes backup.
    final file = await InsecureBackupWriter.writeBackupBlob();
    final contents = await file.readAsString();

    await DvmaEvidence.record(
      InsecureBackupsScreen.vulnId,
      'backup-file',
      'backup-swept file at ${file.path}\n\n$contents',
    );

    if (!mounted) return;
    setState(() {
      _sending = false;
      _path = file.path;
      _contents = contents;
    });
  }

  @override
  Widget build(BuildContext context) {
    final lingo = PlatformLingo.current();
    return VulnDemoScaffold(
      vulnId: InsecureBackupsScreen.vulnId,
      title: 'Insecure Backups',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'android:allowBackup=true with no backup rules (and no iOS '
          'NSURLIsExcludedFromBackupKey) means an unauthenticated backup '
          '(${lingo.backupTool}) captures the full app sandbox - tokens, DBs, '
          'PII. This writes a JSON blob of tokens/PII into the app documents '
          'dir (part of the sandbox a backup sweeps up); the real exploit is '
          '${lingo.backupTool} pulling exactly this file.',
      children: [
        EvidencePanel(
          label: 'backup config',
          value:
              'android:allowBackup = $allowBackup\n'
              'fullBackupContent rules = $fullBackupContent\n'
              'iOS excludedFromBackup = $iosExcludedFromBackup',
        ),
        DemoActionButton(
          label: _sending
              ? 'Writing…'
              : 'Write backup blob (swept by ${lingo.backupTool})',
          onPressed: _sending ? () {} : () => _runBackup(),
        ),
        if (_path != null)
          EvidencePanel(label: 'backup-swept file path', value: _path!),
        if (_contents != null)
          EvidencePanel(label: 'captured by backup', value: _contents!),
      ],
    );
  }
}
