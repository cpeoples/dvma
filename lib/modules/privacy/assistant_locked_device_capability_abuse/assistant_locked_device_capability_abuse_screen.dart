import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/app_intent_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'assistant_gateway.dart';

/// System Assistant -> Locked-Device Capability Abuse.
///
/// The system assistant (Siri / App-Intents / voice shortcut) performs a
/// sensitive capability while the device is LOCKED because the assistant path
/// never re-checks the keyguard.
class AssistantLockedDeviceCapabilityAbuseScreen extends StatefulWidget {
  const AssistantLockedDeviceCapabilityAbuseScreen({super.key});

  static const String vulnId = 'assistant_locked_device_capability_abuse';

  @override
  State<AssistantLockedDeviceCapabilityAbuseScreen> createState() =>
      _AssistantLockedDeviceCapabilityAbuseScreenState();
}

class _AssistantLockedDeviceCapabilityAbuseScreenState
    extends State<AssistantLockedDeviceCapabilityAbuseScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(AssistantResult r) {
    final b = StringBuffer();
    b.writeln('capability             : ${r.capability.name}');
    b.writeln('device locked          : ${r.deviceLocked}');
    b.writeln('performed              : ${r.performed}');
    b.writeln('assistant output       : ${r.output}');
    b.writeln('sensitive while locked : ${r.sensitiveExposedWhileLocked}');
    if (r.denyReason != null) {
      b.writeln('reason                 : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    const gateway = AssistantGateway.lockedSample; // deviceLocked == true
    // VULN: the assistant reads the balance aloud on a LOCKED device.
    final vuln = gateway.invoke(AssistantCapability.readBalance);
    // SECURE: the assistant re-checks the keyguard and refuses.
    final secure = gateway.invokeSafe(AssistantCapability.readBalance);

    // Mirror the capability invoked while locked to the pullable evidence sink.
    DvmaEvidence.record(
      AssistantLockedDeviceCapabilityAbuseScreen.vulnId,
      'assistant-abuse',
      'capability = ${vuln.capability.name}; device locked = ${vuln.deviceLocked}\n'
          'assistant output (while locked): ${vuln.output}\n'
          'sensitive exposed while locked = ${vuln.sensitiveExposedWhileLocked}',
    );

    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // On iOS, drive the real App Intent the assistant would dispatch
    // (UnlockFrontDoorIntent): it declares no authentication policy, so Siri /
    // App Intents run it from a locked device. The native report states the
    // declared policy and the live protected-data (lock) state.
    final native = await AppIntentBridge.invokeSensitiveIntent();
    if (native != null && native.isNotEmpty) {
      await DvmaEvidence.record(
        AssistantLockedDeviceCapabilityAbuseScreen.vulnId,
        'real-appintent-invocation',
        native,
      );
      if (!mounted) return;
      setState(() => _nativeResult = native);
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: AssistantLockedDeviceCapabilityAbuseScreen.vulnId,
      title: 'System Assistant → Locked-Device Capability Abuse',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The system assistant (Siri / App-Intents / a voice shortcut) '
          'exposes sensitive information or performs a privileged capability '
          'while the device is LOCKED because the assistant invocation path '
          'never re-checks the keyguard. An attacker holding a locked phone '
          'triggers the assistant to read the account balance aloud without '
          'ever unlocking. This is the assistant / voice-intent surface '
          'specifically. On iOS the assistant path is backed by a REAL App '
          'Intent (UnlockFrontDoorIntent) shipped in the app binary that '
          'declares no authentication policy, so Siri / App Intents run it from '
          'a locked device; off-iOS it uses a deterministic model. The '
          'secure path re-checks the lock state on the assistant path and '
          'requires unlock/authentication for sensitive capabilities, '
          'returning only non-sensitive results while locked.',
      children: [
        DemoActionButton(
          label: 'Ask assistant for balance on locked device',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'assistant skipped keyguard (leaked while locked)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'assistant re-checked keyguard (requires unlock)',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real iOS App Intent ran from locked device (no auth)',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
