import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/provider_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'file_provider_model.dart';

/// FileProvider Path Traversal / Arbitrary File Sharing.
///
/// An over-broad FileProvider / grantUriPermissions lets another app read
/// arbitrary app-private files via a traversal path.
class FileproviderPathTraversalScreen extends StatefulWidget {
  const FileproviderPathTraversalScreen({super.key});

  static const String vulnId = 'fileprovider_path_traversal';

  @override
  State<FileproviderPathTraversalScreen> createState() =>
      _FileproviderPathTraversalScreenState();
}

class _FileproviderPathTraversalScreenState
    extends State<FileproviderPathTraversalScreen> {
  final _path = TextEditingController(text: '../session.token');
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  Future<void> _run() async {
    final requested = _path.text;
    final resolvedPath = await FileProviderModel.resolvedPath(requested);
    final vuln = await FileProviderModel.resolve(requested);
    final secure = await FileProviderModel.secureResolve(requested);
    // On Android, open the SAME traversal path through the real exported
    // VulnerableProvider's openFile() via the app's ContentResolver, a `../`
    // path escapes the export dir and returns a real FD to an app-private file.
    final native = await ProviderIpcBridge.openTraversal(requested);
    if (native != null && native.isNotEmpty) {
      await DvmaEvidence.record(
        FileproviderPathTraversalScreen.vulnId,
        'path-traversal',
        'exported FileProvider openFile("$requested") returned bytes '
            'outside the export dir:\n$native',
      );
    }
    if (!mounted) return;
    setState(() {
      _vulnResult =
          'resolved: $resolvedPath\n'
          'contents: ${vuln ?? "(not found)"}';
      _secureResult = secure ?? 'REJECTED (path escapes the shared export dir)';
      _nativeResult = native;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: FileproviderPathTraversalScreen.vulnId,
      title: 'FileProvider Path Traversal',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A content resolver joins an attacker-supplied relative path onto the '
          'app-private shared directory without confining the canonical result, '
          'then performs a REAL filesystem read at that path. A "../" path '
          'therefore escapes the export dir and reads arbitrary app-private '
          'files off disk (session tokens, other users\' data). The real '
          'exploit is Android FileProvider-level (an over-broad root-path / '
          'grantUriPermissions resolving a content:// URI containing "..").',
      children: [
        TextField(
          controller: _path,
          decoration: const InputDecoration(
            labelText: 'Requested path (relative to shared/)',
          ),
        ),
        DemoActionButton(
          label: 'Resolve via content provider',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(label: 'vulnerable resolver', value: _vulnResult!),
        if (_secureResult != null)
          EvidencePanel(label: 'confining resolver', value: _secureResult!),
        if (_nativeResult != null)
          EvidencePanel(
            label:
                'exported FileProvider openFile (real FD outside export dir)',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
