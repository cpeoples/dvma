import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'dependency_resolver.dart';

/// Dependency Confusion / Substitution.
///
/// An internal/private package name is resolved from a public registry, so an
/// attacker who publishes that name to the public index gets their impostor
/// pulled into the build (iOS dependency-management research; classic
/// dependency-confusion class).
class DependencyConfusionScreen extends StatefulWidget {
  const DependencyConfusionScreen({super.key});

  static const String vulnId = 'dependency_confusion';

  @override
  State<DependencyConfusionScreen> createState() =>
      _DependencyConfusionScreenState();
}

class _DependencyConfusionScreenState extends State<DependencyConfusionScreen> {
  static const String _pkg = 'acme-internal-auth';

  String? _vulnResult;
  String? _secureResult;

  void _resolve() {
    final vuln = DependencyResolver.resolve(_pkg);
    final secure = DependencyResolver.resolveScoped(_pkg);

    // Mirror the version-race resolution decision (impostor selected) to the
    // pullable evidence sink as the teaching artifact.
    DvmaEvidence.record(
      DependencyConfusionScreen.vulnId,
      'dep-confusion',
      'package = ${vuln.package}\n'
          'version-race resolved: ${vuln.version} from ${vuln.source} '
          '(impostor=${vuln.isImpostor})\n${vuln.reason}\n'
          'scope-pinned would resolve: ${secure.version} from ${secure.source}',
    );

    setState(() {
      _vulnResult =
          'package: ${vuln.package}\n'
          'resolved: ${vuln.version} from ${vuln.source}\n'
          'impostor: ${vuln.isImpostor}\n'
          '${vuln.reason}';
      _secureResult =
          'package: ${secure.package}\n'
          'resolved: ${secure.version} from ${secure.source}\n'
          'impostor: ${secure.isImpostor}\n'
          '${secure.reason}';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: DependencyConfusionScreen.vulnId,
      title: 'Dependency Confusion / Substitution',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The build resolves an internal package name (acme-internal-auth) '
          'from BOTH the private registry and the PUBLIC index and picks the '
          'highest version. The internal package exists privately at 1.2.0, but '
          'an attacker has squatted the same name publicly at 9.9.9 - so the '
          'resolver selects the attacker\'s impostor and pulls it into the '
          'build (the classic dependency-confusion / substitution class). This '
          'is an offline, deterministic model of pubspec / CocoaPods / SPM '
          'resolution: the private and public registries are in-memory maps. '
          'The secure resolver pins internal names to the private registry / '
          'scope and never resolves them from public, returning the trusted '
          '1.2.0.',
      children: [
        DemoActionButton(label: 'Resolve dependencies', onPressed: _resolve),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'version-race resolver (impostor selected)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'scope-pinned resolver (trusted private pkg)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
