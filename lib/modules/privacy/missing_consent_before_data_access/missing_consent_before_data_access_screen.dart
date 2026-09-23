import 'dart:io';

import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Missing Consent Before Data Access.
///
/// Accesses location/contacts/photos with no consent screen.
class MissingConsentBeforeDataAccessScreen extends StatefulWidget {
  const MissingConsentBeforeDataAccessScreen({super.key});

  static const String vulnId = 'missing_consent_before_data_access';

  @override
  State<MissingConsentBeforeDataAccessScreen> createState() =>
      _MissingConsentBeforeDataAccessScreenState();
}

class _MissingConsentBeforeDataAccessScreenState
    extends State<MissingConsentBeforeDataAccessScreen> {
  // VULN: no consent gate. The app reads sensitive data the moment the screen
  // opens (or on first action) without asking or explaining why.
  static const bool consentRequested = false;
  String? _accessed;

  Future<void> _openScreen() async {
    final accessed =
        'read contacts (412 entries)\nread precise location '
        '(37.4219, -122.0840)\nread photo library (1,204 items)\n'
        'consentRequested = $consentRequested';

    // VULN: the sensitive data read without consent is written to a real file
    // on disk (adb/root-pullable), so the no-consent access leaves a durable
    // artifact and is not merely shown in the UI.
    var writtenPath = '(no external dir on this host)';
    try {
      final dirPath = await DvmaEvidence.artifactDirPath();
      final baseDir = dirPath != null
          ? Directory(dirPath)
          : await getApplicationDocumentsDirectory();
      final file = File('${baseDir.path}/no_consent_access.txt');
      await file.parent.create(recursive: true);
      await file.writeAsString(
        '${DateTime.now().toIso8601String()}\n$accessed\n',
        flush: true,
      );
      writtenPath = file.path;
    } catch (_) {
      // Test-safe: the logcat/artifact mirror below still proves the effect.
    }

    // Mirror the accessed-without-consent data to the pullable evidence sink.
    await DvmaEvidence.record(
      MissingConsentBeforeDataAccessScreen.vulnId,
      'no-consent',
      'accessed WITHOUT consent:\n$accessed\nwritten to: $writtenPath',
    );

    if (!mounted) return;
    setState(() => _accessed = '$accessed\nwritten to file: $writtenPath');
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: MissingConsentBeforeDataAccessScreen.vulnId,
      title: 'Missing Consent Before Data Access',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'The app reads contacts, precise location, and the photo library '
          'without ever showing a consent screen or explaining why, then writes '
          'the harvested data to a real on-disk file. Sensitive data access must '
          'be gated on informed, purpose-specific consent.',
      children: [
        DemoActionButton(
          label: 'Open feature (auto-reads data)',
          onPressed: () => _openScreen(),
        ),
        if (_accessed != null)
          EvidencePanel(label: 'accessed with no consent', value: _accessed!),
      ],
    );
  }
}
