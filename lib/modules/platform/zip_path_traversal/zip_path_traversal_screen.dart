import 'package:flutter/material.dart';

import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'zip_slip_unpacker.dart';

/// Zip Path Traversal (Zip-Slip).
///
/// Update-package unpacker writes entries outside the target dir.
class ZipPathTraversalScreen extends StatefulWidget {
  const ZipPathTraversalScreen({super.key});

  static const String vulnId = 'zip_path_traversal';

  @override
  State<ZipPathTraversalScreen> createState() => _ZipPathTraversalScreenState();
}

class _ZipPathTraversalScreenState extends State<ZipPathTraversalScreen> {
  static const String _baseDir = ZipSlipUnpacker.lexicalBaseDir;
  String? _targets;
  String? _verdict;

  Future<void> _unpack() async {
    final zip = ZipSlipUnpacker.craftMaliciousZip();
    // VULN: actually extracts each entry to disk with no containment check, so
    // the `../` entry escapes the extract dir onto the real filesystem.
    final targets = await ZipSlipUnpacker.unpackToDisk(zip);
    if (!mounted) return;
    final escaped = targets
        .where((t) => ZipSlipUnpacker.escapesBase(_baseDir, t))
        .toList();
    setState(() {
      _targets = targets.join('\n');
      _verdict = escaped.isEmpty
          ? 'all entries contained'
          : 'ESCAPED extract dir (written on disk):\n${escaped.join('\n')}';
    });
  }

  @override
  Widget build(BuildContext context) {
    final lingo = PlatformLingo.current();
    return VulnDemoScaffold(
      vulnId: ZipPathTraversalScreen.vulnId,
      title: 'Zip Path Traversal (Zip-Slip)',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The update unpacker joins each zip entry name to the target dir '
          'without verifying the result stays inside it, then WRITES the entry '
          'to disk. A crafted entry '
          '("${ZipSlipUnpacker.maliciousEntry}") escapes into system paths and '
          'overwrites arbitrary files. A real archive is built and each entry '
          'is extracted to a real (${lingo.pullable}) filesystem below; the '
          'traversing entry lands outside the extract dir.',
      children: [
        EvidencePanel(label: 'intended extract dir', value: _baseDir),
        DemoActionButton(label: 'Unpack update.zip', onPressed: _unpack),
        if (_targets != null)
          EvidencePanel(label: 'files written on disk', value: _targets!),
        if (_verdict != null)
          EvidencePanel(label: 'containment check', value: _verdict!),
      ],
    );
  }
}
