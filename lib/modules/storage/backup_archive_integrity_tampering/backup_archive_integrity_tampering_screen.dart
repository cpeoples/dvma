import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'backup_archive.dart';

/// Backup Archive Integrity Tampering.
///
/// The app restores a backup archive of persisted state without verifying its
/// integrity, so an attacker edits the extracted archive (flips is_premium /
/// is_admin, raises the balance) and the app trusts the tampered state.
class BackupArchiveIntegrityTamperingScreen extends StatefulWidget {
  const BackupArchiveIntegrityTamperingScreen({super.key});

  static const String vulnId = 'backup_archive_integrity_tampering';

  @override
  State<BackupArchiveIntegrityTamperingScreen> createState() =>
      _BackupArchiveIntegrityTamperingScreenState();
}

class _BackupArchiveIntegrityTamperingScreenState
    extends State<BackupArchiveIntegrityTamperingScreen> {
  String? _vulnResult;
  String? _secureResult;

  String _render(RestoreResult r) {
    final b = StringBuffer();
    b.writeln('restored           : ${r.restored}');
    b.writeln('integrity verified : ${r.integrityVerified}');
    if (r.restored) {
      b.writeln('is_premium         : ${r.premium}');
      b.writeln('is_admin           : ${r.admin}');
      b.writeln('balance_cents      : ${r.balanceCents}');
    }
    b.writeln('tampered value trusted : ${r.tamperedValueTrusted}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  void _run() {
    final restorer = BackupRestorer();
    // The attacker restores a tampered backup (premium+admin flipped on).
    final tampered = BackupRestorer.tamperedArchive();

    // VULN: restore trusts the archive with no integrity check.
    final vuln = restorer.restore(tampered);

    // SECURE: restoreSafe verifies a keyed MAC and rejects the tampered
    // archive; the genuine archive still verifies and applies.
    final secureTampered = restorer.restoreSafe(tampered);
    final secureGenuine = restorer.restoreSafe(BackupRestorer.genuineArchive());

    setState(() {
      _vulnResult = _render(vuln);
      _secureResult =
          'TAMPERED ARCHIVE (attacker-modified):\n'
          '${_render(secureTampered)}\n\n'
          'GENUINE ARCHIVE (untampered):\n'
          '${_render(secureGenuine)}';
    });

    // real ARTIFACT: write the tampered archive to a real on-disk file (swept
    // by adb backup / pullable), restore FROM it, and mirror to the sink.
    _writeRestoreAndRecord(restorer, tampered);
  }

  Future<void> _writeRestoreAndRecord(
    BackupRestorer restorer,
    BackupArchive tampered,
  ) async {
    // Write the attacker-tampered archive to a real file under app documents.
    final path = await restorer.writeArchiveFile(tampered);
    // VULN: restore FROM the on-disk file with no integrity check.
    final fromFile = await restorer.restoreFromFile();

    final entriesDump = tampered.entries.entries
        .map((e) => '${e.key}=${e.value}')
        .join('\n');
    final artifact =
        '$entriesDump'
        '\n#mac=${tampered.mac ?? ''}  (stale - bound to the ORIGINAL entries)'
        '\n\nrestored from file  : is_premium=${fromFile.premium}, '
        'is_admin=${fromFile.admin}, balance_cents=${fromFile.balanceCents}'
        '\ntampered value trusted : ${fromFile.tamperedValueTrusted}'
        '\n\nbacking file (adb backup / pullable, attacker-editable): $path';
    DvmaEvidence.record(
      BackupArchiveIntegrityTamperingScreen.vulnId,
      'backup',
      artifact,
    );
  }

  @override
  Widget build(BuildContext context) {
    final lingo = PlatformLingo.current();
    return VulnDemoScaffold(
      vulnId: BackupArchiveIntegrityTamperingScreen.vulnId,
      title: 'Backup Archive Integrity Tampering',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The app restores a backup archive of persisted state without '
          'verifying its INTEGRITY. An attacker extracts the backup, edits '
          'security-relevant state (flips is_premium false->true, sets '
          'is_admin, raises the account balance), re-packs it, and restores - '
          'and the restore path applies the attacker-controlled state '
          'verbatim. On device the archive is written to a real file in the '
          'app documents container (swept by ${lingo.backupTool}, '
          'pullable/editable), and the unverified restore reads it back from '
          'disk. The secure path recomputes a keyed MAC over the archive and '
          'refuses any archive whose tag does not verify, while still accepting '
          'the genuine backup.',
      children: [
        DemoActionButton(label: 'Restore tampered backup', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'unverified restore trusts tampered state',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'MAC-verified restore rejects tampering',
            value: _secureResult!,
          ),
      ],
    );
  }
}
