import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'update_installer.dart';

/// Unsigned / Unverified Build Artifact.
///
/// Update artifact fetched and applied with no signature/checksum check.
class UnsignedUnverifiedBuildArtifactScreen extends StatefulWidget {
  const UnsignedUnverifiedBuildArtifactScreen({super.key});

  static const String vulnId = 'unsigned_unverified_build_artifact';

  @override
  State<UnsignedUnverifiedBuildArtifactScreen> createState() =>
      _UnsignedUnverifiedBuildArtifactScreenState();
}

class _UnsignedUnverifiedBuildArtifactScreenState
    extends State<UnsignedUnverifiedBuildArtifactScreen> {
  final _installer = UpdateInstaller();
  final _artifact = TextEditingController(
    text:
        'MALICIOUS_UPDATE_v2.${PlatformLingo.current().appPackageExt} '
        '(swapped by MITM)',
  );
  String? _result;

  Future<void> _apply() async {
    final bytes = _artifact.text;
    // VULN (unchanged): apply with no signature/checksum verification.
    final summary = _installer.apply(bytes);
    // VULN (real I/O): write the unsigned artifact bytes to a real file on disk
    // (never verifying the signature first).
    final path = await _installer.applyToDisk(bytes);

    // Mirror the installed unsigned artifact to the pullable evidence sink.
    await DvmaEvidence.record(
      UnsignedUnverifiedBuildArtifactScreen.vulnId,
      'unsigned-artifact',
      '$summary\nwritten (unverified) to: $path\n'
          'sha256=${UpdateInstaller.sha256Of(bytes)}',
    );

    if (!mounted) return;
    setState(() => _result = '$summary\nwritten to disk: $path');
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: UnsignedUnverifiedBuildArtifactScreen.vulnId,
      title: 'Unsigned / Unverified Build Artifact',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The in-app updater fetches an artifact over the network and applies '
          'it with no signature and no checksum comparison against a trusted '
          'value. An on-path attacker swaps in a trojaned artifact and it '
          'installs unchanged. Apply a "tampered" artifact below.',
      children: [
        TextField(
          controller: _artifact,
          decoration: const InputDecoration(labelText: 'fetched artifact'),
        ),
        DemoActionButton(label: 'Apply update', onPressed: () => _apply()),
        if (_result != null)
          EvidencePanel(label: 'install result', value: _result!),
      ],
    );
  }
}
