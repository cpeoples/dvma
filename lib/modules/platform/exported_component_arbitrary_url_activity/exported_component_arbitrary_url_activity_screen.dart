import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/component_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'exported_launcher.dart';

/// Exported Component -> Arbitrary URL / Activity Launch.
///
/// An exported component accepts an attacker-supplied URL/activity target and
/// opens it with the app's identity/privileges (ABEMA CVE-2024-28745 / Samsung
/// Members CVE-2026-20985 & CVE-2025-21079 class).
class ExportedComponentArbitraryUrlActivityScreen extends StatefulWidget {
  const ExportedComponentArbitraryUrlActivityScreen({super.key});

  static const String vulnId = 'exported_component_arbitrary_url_activity';

  @override
  State<ExportedComponentArbitraryUrlActivityScreen> createState() =>
      _ExportedComponentArbitraryUrlActivityScreenState();
}

class _ExportedComponentArbitraryUrlActivityScreenState
    extends State<ExportedComponentArbitraryUrlActivityScreen> {
  final TextEditingController _urlController = TextEditingController(
    text: 'https://evil.example/attacker',
  );
  final TextEditingController _activityController = TextEditingController(
    text: 'InternalAdminActivity',
  );

  String? _vulnResult;
  String? _secureResult;
  String? _nativeApplied;

  Map<String, String> _extras() => {
    'target': _urlController.text.trim(),
    'activity': _activityController.text.trim(),
  };

  Future<void> _deliver() async {
    final extras = _extras();
    final vuln = ExportedLauncher.handleExternalIntent(extras);
    final secure = ExportedLauncher.handleExternalIntentSafe(extras);

    // On Android, actively start DVMA's real exported UrlDispatchActivity
    // in-process with the attacker-supplied target/activity extras, and read
    // back what it opened.
    final applied = await ComponentIpcBridge.startUrlDispatch(
      target: extras['target'],
      activity: extras['activity'],
    );
    if (applied != null) {
      await DvmaEvidence.record(
        ExportedComponentArbitraryUrlActivityScreen.vulnId,
        'exported-activity-opened-target',
        'exported component opened attacker target: $applied',
      );
    }

    setState(() {
      _vulnResult =
          'opened: ${vuln.opened}\n'
          'privileged: ${vuln.privileged}\n'
          '${vuln.description}';
      _secureResult = 'opened: ${secure.opened}\n${secure.description}';
      _nativeApplied = applied;
    });
  }

  @override
  void dispose() {
    _urlController.dispose();
    _activityController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ExportedComponentArbitraryUrlActivityScreen.vulnId,
      title: 'Exported Component -> Arbitrary URL / Activity Launch',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'An exported component reads attacker-supplied extras naming a URL '
          'and/or an activity and opens whatever is named - with THIS app\'s '
          'identity and privileges. With no allowlist, another app can point it '
          'at an arbitrary URL or, worse, a privileged INTERNAL activity '
          '(admin/debug/session-export) that should only be reachable '
          'in-process (the ABEMA CVE-2024-28745 / Samsung Members '
          'CVE-2026-20985 & CVE-2025-21079 class). This is an offline, '
          'deterministic simulation: the Intent is a Map of extras and '
          '"opening" returns a descriptor of what would launch. The secure '
          'handler allowlists only public activities and first-party https URLs.',
      children: [
        Padding(
          padding: const EdgeInsets.only(top: DvmaSpacing.md),
          child: TextField(
            controller: _urlController,
            decoration: const InputDecoration(
              labelText: 'target URL extra',
              hintText: 'https://evil.example/attacker',
              border: OutlineInputBorder(),
            ),
          ),
        ),
        Padding(
          padding: const EdgeInsets.only(top: DvmaSpacing.md),
          child: TextField(
            controller: _activityController,
            decoration: const InputDecoration(
              labelText: 'activity extra',
              hintText: 'InternalAdminActivity',
              border: OutlineInputBorder(),
            ),
          ),
        ),
        DemoActionButton(label: 'Deliver external intent', onPressed: _deliver),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'exported component (opens arbitrary target)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'allowlisted component (rejects)',
            value: _secureResult!,
          ),
        if (_nativeApplied != null)
          EvidencePanel(
            label: 'real exported UrlDispatchActivity opened attacker target',
            value: _nativeApplied!,
          ),
      ],
    );
  }
}
