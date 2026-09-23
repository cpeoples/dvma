import 'dart:async';

import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'bom_inventory.dart';

/// Missing / Stale SBOM (No Component Inventory).
///
/// The app bundles several third-party SDKs - some pinned to known-vulnerable
/// versions - but produces no Software Bill of Materials, so defenders are
/// blind to them.
class SbomMissingOrStaleScreen extends StatefulWidget {
  const SbomMissingOrStaleScreen({super.key});

  static const String vulnId = 'sbom_missing_or_stale';

  @override
  State<SbomMissingOrStaleScreen> createState() =>
      _SbomMissingOrStaleScreenState();
}

class _SbomMissingOrStaleScreenState extends State<SbomMissingOrStaleScreen> {
  String? _blindResult;
  String? _sbomResult;
  String? _auditResult;
  String? _sbomFile;

  void _runBlind() {
    final findings = BomInventory.knownVulnerableComponents();
    setState(() {
      _blindResult = findings.isEmpty
          ? '0 vulnerable components found.\n'
                '(No SBOM => nothing declared => nothing to audit. '
                'The bundled SDKs are invisible.)'
          : findings.map((f) => f.toString()).join('\n');
    });
  }

  void _runAudit() {
    final sbom = BomInventory.generateSbom();
    final findings = BomInventory.auditAgainstAdvisories(sbom);
    setState(() {
      final components = (sbom['components'] as List).cast<Map>();
      _sbomResult = components
          .map((c) => '${c['name']} ${c['version']}  (${c['purl']})')
          .join('\n');
      _auditResult = findings.map((f) => f.toString()).join('\n\n');
    });

    // SECURE (real I/O): write the generated SBOM to a real file on disk, then
    // mirror the artifact path + audit findings to the pullable evidence sink.
    unawaited(_writeSbom(findings));
  }

  Future<void> _writeSbom(List<AuditedComponent> findings) async {
    final path = await BomInventory.writeSbomToFile();
    await DvmaEvidence.record(
      SbomMissingOrStaleScreen.vulnId,
      'sbom',
      'CycloneDX SBOM generated from in-code component inventory '
          '(pubspec.lock not bundled as an asset; real build: `dart pub deps '
          '--json`)\nwritten to: $path\n'
          'audit findings:\n${findings.map((f) => f.toString()).join('\n')}',
    );
    if (!mounted) return;
    setState(
      () => _sbomFile =
          'SBOM written to (${PlatformLingo.current().pullable}):\n'
          '$path\n\n'
          '(generate in a real build with: dart pub deps --json)',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: SbomMissingOrStaleScreen.vulnId,
      title: 'Missing / Stale SBOM',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'The app bundles third-party SDKs (image_loader, analytics_sdk, '
          'net_http, ...) and some are pinned to versions with publicly-known '
          'CVEs. But the build ships NO Software Bill of Materials, so there is '
          'no component inventory to cross-reference against advisory feeds. '
          'You cannot audit what you never inventoried, so the vulnerable '
          'components stay invisible - the same blind spot that lets a stale, '
          'known-vulnerable SDK ride along in a release. This is an '
          'offline/deterministic simulation: the "advisory feed" is a local '
          'map. Generating an SBOM (CycloneDX) and auditing it surfaces the '
          'exact components that the blind path misses.',
      children: [
        DemoActionButton(
          label: 'Ask app for vulnerable components (no SBOM)',
          onPressed: _runBlind,
        ),
        if (_blindResult != null)
          EvidencePanel(
            label: 'blind path: what the app declares',
            value: _blindResult!,
          ),
        DemoActionButton(
          label: 'Generate SBOM + audit against advisories',
          onPressed: _runAudit,
        ),
        if (_sbomResult != null)
          EvidencePanel(
            label: 'generated SBOM (CycloneDX components)',
            value: _sbomResult!,
          ),
        if (_auditResult != null)
          EvidencePanel(
            label: 'audit findings (surfaced only WITH an SBOM)',
            value: _auditResult!,
          ),
        if (_sbomFile != null)
          EvidencePanel(
            label: 'generated SBOM written to disk (recoverable artifact)',
            value: _sbomFile!,
          ),
      ],
    );
  }
}
