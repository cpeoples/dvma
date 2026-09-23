import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/provider_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'file_import_provider.dart';

/// ContentProvider File-Import Filename Path Traversal.
///
/// A file-import API joins the caller-supplied display name under app storage
/// with no canonicalization, so a `../` filename escapes the import dir and
/// overwrites arbitrary app files (CVE-2025-65814 / CVE-2025-65815 class).
class ContentproviderFilenamePathTraversalScreen extends StatefulWidget {
  const ContentproviderFilenamePathTraversalScreen({super.key});

  static const String vulnId = 'contentprovider_filename_path_traversal';

  @override
  State<ContentproviderFilenamePathTraversalScreen> createState() =>
      _ContentproviderFilenamePathTraversalScreenState();
}

class _ContentproviderFilenamePathTraversalScreenState
    extends State<ContentproviderFilenamePathTraversalScreen> {
  final _name = TextEditingController(
    text: FileImportProvider.traversalDisplayName,
  );
  static const String _attackerBytes =
      '<map><string name="auth_token">ATTACKER-OWNED</string></map>';

  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(ImportResult r, String secretsNow, String importRoot) {
    final b = StringBuffer();
    b.writeln('resolved path      : ${r.resolvedPath}');
    b.writeln('wrote              : ${r.wrote}');
    b.writeln('blocked            : ${r.blocked}');
    b.writeln(
      'escaped import dir : '
      '${r.escapedImportRoot(importRoot)}',
    );
    if (r.reason != null) {
      b.writeln('note               : ${r.reason}');
    }
    b.writeln('secrets.xml now    : $secretsNow');
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    final requested = _name.text;
    // VULN: the display name traverses out of the import dir and clobbers the
    // app's secrets file on the real filesystem.
    final vulnProvider = await FileImportProvider.seeded(tag: 'vuln');
    final vuln = await vulnProvider.importFile(requested, _attackerBytes);
    final vulnSecrets =
        await vulnProvider.fileAt(vulnProvider.instanceSecretsPath) ??
        '(missing)';
    // SECURE: the same display name is rejected; secrets stay intact.
    final secureProvider = await FileImportProvider.seeded(tag: 'secure');
    final secure = await secureProvider.importFileSafe(
      requested,
      _attackerBytes,
    );
    final secureSecrets =
        await secureProvider.fileAt(secureProvider.instanceSecretsPath) ??
        '(missing)';
    // On Android, exercise the real exported provider: reading
    // content://com.dvma.provider.vuln/files/<display name> with a `../`
    // display name traverses out of the export dir and reads an app-private
    // file off disk through openFile().
    final native = await ProviderIpcBridge.openTraversal(requested);
    if (native != null && native.isNotEmpty) {
      await DvmaEvidence.record(
        ContentproviderFilenamePathTraversalScreen.vulnId,
        'path-traversal',
        'exported provider resolved display name "$requested" outside the '
            'import dir:\n$native',
      );
    }
    if (!mounted) return;
    setState(() {
      _vulnResult = _render(vuln, vulnSecrets, vulnProvider.instanceImportRoot);
      _secureResult = _render(
        secure,
        secureSecrets,
        secureProvider.instanceImportRoot,
      );
      _nativeResult = native;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ContentproviderFilenamePathTraversalScreen.vulnId,
      title: 'ContentProvider File-Import Filename Path Traversal',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'A ContentProvider / file-import API takes the CALLER-SUPPLIED display '
          'name and joins it under the app\'s import directory with NO '
          'canonicalization, then WRITES the bytes there on the real '
          'filesystem. A "../" filename therefore traverses OUT of the '
          'import dir and overwrites/reads arbitrary app-private files - here '
          'the crafted display name "../../shared_prefs/secrets.xml" escapes '
          'and '
          'clobbers the app\'s stored auth token on disk (the Android '
          'ContentProvider import-traversal CVE-2025-65814 / CVE-2025-65815 '
          'class). The secure path '
          'strips path separators, canonicalizes, and confines the result under '
          'the import root, rejecting the traversal so the secrets survive.',
      children: [
        TextField(
          controller: _name,
          decoration: const InputDecoration(
            labelText: 'Import display name (attacker-supplied)',
          ),
        ),
        DemoActionButton(label: 'Import file', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'no canonicalization (secrets overwritten)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'confined to import root (rejected)',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'exported provider read outside import dir (real openFile)',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
