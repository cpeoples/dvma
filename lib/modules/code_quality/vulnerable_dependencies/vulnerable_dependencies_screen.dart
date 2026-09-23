import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Vulnerable Dependencies (known CVE).
///
/// Bundles a library version with a documented known CVE.
class VulnerableDependenciesScreen extends StatefulWidget {
  const VulnerableDependenciesScreen({super.key});

  static const String vulnId = 'vulnerable_dependencies';

  @override
  State<VulnerableDependenciesScreen> createState() =>
      _VulnerableDependenciesScreenState();
}

class _VulnerableDependenciesScreenState
    extends State<VulnerableDependenciesScreen> {
  // A real, resolvable direct dependency that is genuinely outdated in this
  // project's pubspec.lock. `dart_jsonwebtoken` is pinned to a version a full
  // major behind the latest (2.17.0 vs 3.4.1). `dart pub outdated` lists it as
  // outdated, and because it is a JWT verification library, running behind on
  // it is a real security-relevant supply-chain exposure. Keep in sync with
  // pubspec.yaml. (We deliberately do not pin an artificial CVE'd package that
  // would break dependency resolution against image/flutter_launcher_icons.)
  static const String _depName = 'dart_jsonwebtoken';
  static const String _depVersion = '2.17.0';
  static const String _latestVersion = '3.4.1';
  static const List<Map<String, String>> _deps = [
    {
      'name': _depName,
      'version': _depVersion,
      'cve': 'outdated (latest $_latestVersion - a full major behind)',
      'issue':
          'JWT verification library kept behind on security fixes; known-'
          'vulnerable JWT-library versions are a classic supply-chain exposure',
    },
    {
      'name': 'app_links',
      'version': '6.4.1',
      'cve': 'outdated (latest 7.2.1)',
      'issue': 'deep-link handling library behind current release',
    },
  ];

  /// Command a trainee runs to confirm the advisory against the real project.
  static const String _scanCmd =
      'dart pub outdated   # lists $_depName $_depVersion as outdated; or: '
      'osv-scanner --lockfile=pubspec.lock';

  String? _scan;

  void _scan2() {
    final findings = _deps
        .map(
          (d) => '${d['name']}@${d['version']}  ${d['cve']}  -> ${d['issue']}',
        )
        .join('\n');

    // Mirror the real outdated deps + scan command to the evidence sink.
    DvmaEvidence.record(
      VulnerableDependenciesScreen.vulnId,
      'vulnerable-dep',
      '$_depName $_depVersion (pubspec.yaml) - outdated, latest '
          '$_latestVersion. Running a JWT library a full major behind is a '
          'real supply-chain exposure.\nverify: $_scanCmd',
    );

    setState(
      () => _scan =
          'dart pub outdated / osv-scanner flag real outdated dependencies in '
          'this project (verifiable against pubspec.lock):\n$findings\n'
          'verify: $_scanCmd',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: VulnerableDependenciesScreen.vulnId,
      title: 'Vulnerable Dependencies',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The project really pins $_depName $_depVersion in pubspec.yaml - a '
          'JWT verification library a full major version behind the latest '
          '($_latestVersion) - and never updates it. Running security-relevant '
          'dependencies behind current releases is a real supply-chain risk. '
          'Run `dart pub outdated` (it lists the pin as outdated) or OSV-Scanner '
          'on pubspec.lock to flag it. The entries below mirror the real tree.',
      children: [
        EvidencePanel(
          label: 'outdated dependencies (pubspec.yaml / pubspec.lock)',
          value: '$_depName: $_depVersion  (latest $_latestVersion)',
        ),
        DemoActionButton(label: 'Run dart pub outdated', onPressed: _scan2),
        if (_scan != null) EvidencePanel(label: 'scan results', value: _scan!),
      ],
    );
  }
}
