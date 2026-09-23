import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/resilience_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Device Attestation Not Implemented.
///
/// The app trusts the client environment for a sensitive action without
/// requesting a hardware-backed device-integrity verdict (Play Integrity on
/// Android, DeviceCheck / App Attest on iOS). A rooted, emulated, or tampered
/// device is treated exactly like a genuine one, the missing control is the
/// weakness (MASWE-0054).
class DeviceAttestationAbsentScreen extends StatefulWidget {
  const DeviceAttestationAbsentScreen({super.key});

  static const String vulnId = 'device_attestation_absent';

  @override
  State<DeviceAttestationAbsentScreen> createState() =>
      _DeviceAttestationAbsentScreenState();
}

class _DeviceAttestationAbsentScreenState
    extends State<DeviceAttestationAbsentScreen> {
  String? _result;

  Future<void> _run() async {
    // Gather the real device-integrity signals the app *could* consult (the
    // same native probes the resilience bypass modules use), then proceed with
    // the sensitive action anyway, the missing control is that nothing gates
    // on this verdict.
    final root = await ResilienceBridge.rootCheck();
    final emulator = await ResilienceBridge.emulatorCheck();
    final debugger = await ResilienceBridge.debuggerCheck();
    final signals = {'root': root, 'emulator': emulator, 'debugger': debugger}
      ..removeWhere((_, v) => v == null);

    final available = signals.isNotEmpty;
    final verdict = available
        ? signals.entries.map((e) => '${e.key}: ${e.value}').join('\n')
        : '(native probes unavailable on this host)';

    if (!mounted) return;
    setState(
      () => _result =
          'real device signals available: $available\n'
          'hardware-backed verdict requested: false\n'
          'action allowed regardless of the signals below: true\n\n$verdict',
    );
    DvmaEvidence.record(
      DeviceAttestationAbsentScreen.vulnId,
      'device-attestation-absent',
      'sensitive action proceeded with no hardware-backed device-integrity '
          'verdict (no Play Integrity / DeviceCheck / App Attest). Real signals '
          'the app ignored:\n$verdict',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: DeviceAttestationAbsentScreen.vulnId,
      title: 'Device Attestation Not Implemented',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The app performs a sensitive action while trusting the client '
          'environment, without requesting a hardware-backed device-integrity '
          'verdict (Play Integrity on Android, DeviceCheck / App Attest on '
          'iOS). It gathers the REAL root / emulator / debugger signals below '
          'via the native probe, then proceeds regardless: a rooted, emulated, '
          'or tampered device is accepted identically to a genuine one - the '
          'missing control is the weakness.',
      children: [
        DemoActionButton(label: 'Perform sensitive action', onPressed: _run),
        if (_result != null)
          EvidencePanel(label: 'real signals the app ignored', value: _result!),
      ],
    );
  }
}
