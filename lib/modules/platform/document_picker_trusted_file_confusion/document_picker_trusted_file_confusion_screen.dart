import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'document_importer.dart';

/// Document-Picker Trusted-File Confusion.
///
/// The app assumes a file returned by the system document picker is trustworthy
/// and feeds its declared type/path into a sensitive sink with no
/// re-validation.
class DocumentPickerTrustedFileConfusionScreen extends StatefulWidget {
  const DocumentPickerTrustedFileConfusionScreen({super.key});

  static const String vulnId = 'document_picker_trusted_file_confusion';

  @override
  State<DocumentPickerTrustedFileConfusionScreen> createState() =>
      _DocumentPickerTrustedFileConfusionScreenState();
}

class _DocumentPickerTrustedFileConfusionScreenState
    extends State<DocumentPickerTrustedFileConfusionScreen> {
  String? _vulnResult;
  String? _secureResult;

  String _render(PickedDocument doc, ImportOutcome r) {
    final b = StringBuffer();
    b.writeln('declared name      : ${doc.declaredName}');
    b.writeln('declared mime      : ${doc.declaredMimeType}');
    b.writeln('real (off-disk)type: ${r.sniffedType}');
    b.writeln('declared path      : ${doc.declaredPath}');
    b.writeln('canonical path     : ${r.realPath}');
    if (r.artifactPath != null) {
      b.writeln('temp file written  : ${r.artifactPath}');
    }
    b.writeln('imported           : ${r.imported}');
    b.writeln('trusted as type    : ${r.trustedType ?? '(none)'}');
    b.writeln('executed as code   : ${r.executedAsCode}');
    b.writeln('escaped sandbox    : ${r.escapedSandbox}');
    if (r.reason != null) {
      b.writeln('reason             : ${r.reason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    const importer = DocumentImporter();
    const doc = DocumentImporter.hostile;

    // VULN: write the picked bytes to a real temp file, then trust the declared
    // ".txt"/text/plain claim and path.
    final vuln = await importer.importReal(doc);

    // SECURE: re-read the real magic bytes off disk + confine the canonical
    // path -> refused.
    final secure = await importer.importSafeReal(doc);

    // real artifact: record the trusted-file confusion - a file that claimed a
    // harmless type but was parsed/executed as code and escaped the sandbox.
    await DvmaEvidence.record(
      DocumentPickerTrustedFileConfusionScreen.vulnId,
      'file-confusion',
      'picker doc declaredName=${doc.declaredName} '
          'declaredMime=${doc.declaredMimeType} sniffedOffDisk=${vuln.sniffedType} '
          'declaredPath=${doc.declaredPath} canonicalPath=${vuln.realPath} '
          'tempFile=${vuln.artifactPath ?? '(offline)'} imported=${vuln.imported} '
          'executedAsCode=${vuln.executedAsCode} escapedSandbox=${vuln.escapedSandbox}',
    );
    if (!mounted) return;
    setState(() {
      _vulnResult = _render(doc, vuln);
      _secureResult = _render(doc, secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: DocumentPickerTrustedFileConfusionScreen.vulnId,
      title: 'Document-Picker Trusted-File Confusion',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The app assumes a file returned by the system document/file picker '
          '(or a security-scoped URL) is trustworthy just because the OS '
          'handed it over. It feeds the declared type/name/path into a '
          'sensitive sink with no re-validation, so a document that claims to '
          'be a harmless "text/plain" .txt - but whose real bytes are an '
          'executable script - is parsed/executed, and its declared path is '
          'followed into a privileged location. The picked bytes are written to '
          'a real temp file and the magic bytes are re-read OFF DISK; the secure '
          'path re-validates that real content type and confines the canonical '
          'path under the import sandbox.',
      children: [
        DemoActionButton(label: 'Import file from picker', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'declared type/path trusted',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'real content re-validated + path confined',
            value: _secureResult!,
          ),
      ],
    );
  }
}
