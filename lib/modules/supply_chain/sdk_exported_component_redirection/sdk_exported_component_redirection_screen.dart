import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'vulnerable_sdk_component.dart';

/// Bundled SDK Ships a Vulnerable Exported Component.
///
/// A bundled third-party SDK ships its own vulnerable exported component that
/// performs intent redirection, so another app abuses the SDK (not the host
/// app's code) to reach private data / credentials (EngageLab SDK, 50M+
/// installs).
class SdkExportedComponentRedirectionScreen extends StatefulWidget {
  const SdkExportedComponentRedirectionScreen({super.key});

  static const String vulnId = 'sdk_exported_component_redirection';

  @override
  State<SdkExportedComponentRedirectionScreen> createState() =>
      _SdkExportedComponentRedirectionScreenState();
}

class _SdkExportedComponentRedirectionScreenState
    extends State<SdkExportedComponentRedirectionScreen> {
  final TextEditingController _targetController = TextEditingController(
    text: 'AccountCredentialsProvider',
  );

  String? _vulnResult;
  String? _secureResult;

  Map<String, Object?> _intent() => {
    'forward': {
      'target': _targetController.text.trim(),
      'extras': const {'callback': 'com.evil.app/exfil'},
    },
  };

  void _deliver() {
    final intent = _intent();
    final vuln = VulnerableSdkComponent.handleForwardedIntent(intent);
    final secure = VulnerableSdkComponent.handleForwardedIntentSafe(intent);

    // Mirror the redirected private-component invocation to the pullable
    // evidence sink (native intent wiring is out of scope, record the
    // decision + any data the SDK reached with host privileges).
    DvmaEvidence.record(
      SdkExportedComponentRedirectionScreen.vulnId,
      'sdk-redirect',
      'forwarded target = ${vuln.target}\n'
          'redirected = ${vuln.redirected}\n'
          'leaked (host-privileged): ${vuln.leakedData ?? '(none)'}\n'
          '${vuln.reason}',
    );

    setState(() {
      _vulnResult =
          'redirected: ${vuln.redirected}\n'
          'target: ${vuln.target}\n'
          'leaked: ${vuln.leakedData ?? '(none)'}\n'
          '${vuln.reason}';
      _secureResult =
          'redirected: ${secure.redirected}\n'
          'target: ${secure.target}\n'
          '${secure.reason}';
    });
  }

  @override
  void dispose() {
    _targetController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: SdkExportedComponentRedirectionScreen.vulnId,
      title: 'Bundled SDK Ships a Vulnerable Exported Component',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The vulnerability is NOT in the host app\'s own code - it ships '
          'inside a bundled third-party SDK (the EngageLab SDK class, 50M+ '
          'installs). The SDK\'s exported component takes a forwarded/nested '
          'intent and redirects to the embedded target WITHOUT validating the '
          'destination. Because the SDK runs with the HOST app\'s identity and '
          'permissions, another app can route the redirect at a PRIVATE '
          'component (an internal AccountCredentialsProvider) and exfiltrate '
          'credentials the host can reach. The lesson: auditing your own code '
          'is not enough - a dependency\'s exported component can expose you, '
          'and only updating/removing the SDK (or the platform hardening it) '
          'fixes it. This is an offline, deterministic simulation. The secure '
          'handler allowlists only the SDK\'s own public endpoints and refuses '
          'external/private redirect targets.',
      children: [
        Padding(
          padding: const EdgeInsets.only(top: DvmaSpacing.md),
          child: TextField(
            controller: _targetController,
            decoration: const InputDecoration(
              labelText: 'forwarded intent target',
              hintText: 'AccountCredentialsProvider',
              border: OutlineInputBorder(),
            ),
          ),
        ),
        DemoActionButton(
          label: 'Deliver intent to SDK component',
          onPressed: _deliver,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'SDK component (redirects to private target, leaks data)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'allowlisted SDK component (rejects)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
