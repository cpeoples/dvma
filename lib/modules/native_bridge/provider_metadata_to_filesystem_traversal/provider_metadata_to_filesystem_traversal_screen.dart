import 'package:flutter/material.dart';

import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'file_picker_plugin.dart';

/// Provider-Controlled Metadata -> Plugin Filesystem Traversal.
///
/// A plugin reads DISPLAY_NAME from an untrusted ContentProvider and joins it
/// into a filesystem path with no sanitization, so a malicious provider's
/// `../` name escapes the plugin cache (Flutter file_picker CVE-2026-38093
/// class). The app calls an innocent `pick()`; the danger is in the plugin.
class ProviderMetadataToFilesystemTraversalScreen extends StatefulWidget {
  const ProviderMetadataToFilesystemTraversalScreen({super.key});

  static const String vulnId = 'provider_metadata_to_filesystem_traversal';

  @override
  State<ProviderMetadataToFilesystemTraversalScreen> createState() =>
      _ProviderMetadataToFilesystemTraversalScreenState();
}

class _ProviderMetadataToFilesystemTraversalScreenState
    extends State<ProviderMetadataToFilesystemTraversalScreen> {
  String? _vulnResult;
  String? _secureResult;

  String _render(PickResult r) {
    final b = StringBuffer();
    b.writeln('provider name    : ${r.displayName}');
    b.writeln('resolved path    : ${r.resolvedPath}');
    b.writeln('wrote            : ${r.wrote}');
    b.writeln('escaped cache    : ${r.escapedCacheRoot}');
    b.writeln('blocked          : ${r.blocked}');
    if (r.readBack != null) {
      b.writeln('contents now     : ${r.readBack}');
    }
    if (r.reason != null) {
      b.writeln('reason           : ${r.reason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // The app calls the innocent-looking pick(); a MALICIOUS provider supplies
    // a `../` display name. The dangerous join happens inside the plugin and
    // clobbers the app's real secrets file on disk.
    final vulnPlugin = await FilePickerPlugin.seeded(tag: 'vuln');
    final vuln = await vulnPlugin.pickAndCache(ContentProvider.malicious);
    final vulnSecrets =
        await vulnPlugin.fileAt(vulnPlugin.instanceSecretsPath) ?? '(missing)';

    final securePlugin = await FilePickerPlugin.seeded(tag: 'secure');
    final secure = await securePlugin.pickAndCacheSafe(
      ContentProvider.malicious,
    );
    final secureSecrets =
        await securePlugin.fileAt(securePlugin.instanceSecretsPath) ??
        '(missing)';
    if (!mounted) return;
    setState(() {
      _vulnResult = '${_render(vuln)}\nsecrets now      : $vulnSecrets';
      _secureResult = '${_render(secure)}\nsecrets now      : $secureSecrets';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ProviderMetadataToFilesystemTraversalScreen.vulnId,
      title: 'Provider Metadata → Plugin Filesystem Traversal',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A framework/plugin layer reads DISPLAY_NAME from an UNTRUSTED '
          'ContentProvider and uses it directly in filesystem path '
          'construction with no sanitization. The app author calls an '
          'innocent-looking pick() API, but inside the plugin a malicious '
          'provider\'s "../" display name traverses out of the plugin cache '
          'and clobbers the app\'s shared_prefs secrets on disk (Flutter '
          'file_picker CVE-2026-38093 class). On device this performs a real '
          'File(cacheRoot, displayName) write. The secure path takes the '
          'basename / canonicalizes and confines the write under the plugin '
          'cache root.',
      children: [
        DemoActionButton(
          label: 'Pick file from malicious provider',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'plugin joined provider name (escaped cache, clobbered)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'basename + confinement in plugin (refused)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
