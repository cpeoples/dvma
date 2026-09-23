import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/resilience_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// App Attestation Not Implemented.
///
/// The backend accepts requests without an app-attestation token proving they
/// come from a genuine, unmodified build (Play Integrity app-recognition on
/// Android, App Attest on iOS). A repackaged or scripted client is
/// indistinguishable from the real app, the missing control is the weakness
/// (MASWE-0056).
class AppAttestationAbsentScreen extends StatefulWidget {
  const AppAttestationAbsentScreen({super.key});

  static const String vulnId = 'app_attestation_absent';

  @override
  State<AppAttestationAbsentScreen> createState() =>
      _AppAttestationAbsentScreenState();
}

class _AppAttestationAbsentScreenState
    extends State<AppAttestationAbsentScreen> {
  String? _result;

  Future<void> _run() async {
    // The real signing identity that an app-attestation token would bind the
    // request to. The app knows it, but attaches no attestation token to the
    // backend request, so a repackaged/scripted client is indistinguishable.
    final signing = await ResilienceBridge.tamperCheck();
    final known = signing != null;

    if (!mounted) return;
    setState(
      () => _result =
          'attestation token attached to request: none\n'
          'server accepts request: true\n'
          'real signing identity available to bind against: $known\n\n'
          '${signing ?? "(native probe unavailable on this host)"}\n\n'
          'a repackaged APK/IPA or a scripted client (curl/Frida) is accepted '
          'identically to the genuine, signed app.',
    );
    DvmaEvidence.record(
      AppAttestationAbsentScreen.vulnId,
      'app-attestation-absent',
      'backend request carried no app-attestation token; the genuine signing '
          'identity below was never bound to the request, so a repackaged or '
          'scripted client cannot be distinguished from the real build:\n'
          '${signing ?? "(unavailable)"}',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: AppAttestationAbsentScreen.vulnId,
      title: 'App Attestation Not Implemented',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The backend accepts requests without an app-attestation token '
          'proving they come from a genuine, unmodified build (Play Integrity '
          'app recognition on Android, App Attest on iOS). The app reads its '
          'REAL signing certificate below - the identity an attestation token '
          'would bind against - but attaches nothing to the request, so a '
          'repackaged or scripted client is indistinguishable from the real '
          'app. The missing control is the weakness.',
      children: [
        DemoActionButton(label: 'Send backend request', onPressed: _run),
        if (_result != null)
          EvidencePanel(
            label: 'real signing identity, unbound',
            value: _result!,
          ),
      ],
    );
  }
}
