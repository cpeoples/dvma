import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/app_intent_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'control_widget_intent.dart';

/// Lock-Screen Control / Widget Action Authorization.
///
/// A Control Widget invokes a sensitive App Intent from the lock screen of a
/// locked device with no authentication. The secure path requires unlock /
/// biometric for sensitive intents regardless of surface.
class LockscreenControlActionAuthorizationScreen extends StatefulWidget {
  const LockscreenControlActionAuthorizationScreen({super.key});

  static const String vulnId = 'lockscreen_control_action_authorization';

  @override
  State<LockscreenControlActionAuthorizationScreen> createState() =>
      _LockscreenControlActionAuthorizationScreenState();
}

class _LockscreenControlActionAuthorizationScreenState
    extends State<LockscreenControlActionAuthorizationScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  String _render(IntentInvocationResult r) {
    final b = StringBuffer();
    b.writeln('intent        : ${r.intent.name}');
    b.writeln('sensitive     : ${r.intent.sensitive}');
    b.writeln('surface       : ${r.surface.name}');
    b.writeln('device locked : ${r.deviceLocked}');
    b.writeln('performed     : ${r.performed}');
    b.writeln('auth required : ${r.authRequired}');
    b.writeln('unsafe        : ${r.unsafe}');
    if (r.denyReason != null) {
      b.writeln('deny reason   : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    final runner = ControlWidgetIntentRunner();

    // VULN: unlock the front door straight from the lock screen of a locked
    // device with no auth.
    final vuln = runner.invoke(
      ControlWidgetIntentRunner.unlockFrontDoor,
      Surface.lockScreen,
      deviceLocked: true,
    );

    // SECURE: the same invocation is deferred until the device is unlocked.
    final secure = runner.invokeSafe(
      ControlWidgetIntentRunner.unlockFrontDoor,
      Surface.lockScreen,
      deviceLocked: true,
    );

    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // Real device-extractable artifact: a sensitive intent performed from a
    // locked device with no authentication.
    if (vuln.performed && vuln.unsafe) {
      await DvmaEvidence.record(
        LockscreenControlActionAuthorizationScreen.vulnId,
        'lockscreen-privileged-intent',
        _render(vuln),
      );
    }

    // On iOS, drive the real App Intent (UnlockFrontDoorIntent) shipped in the
    // Runner binary: it declares no authentication policy, so the system runs
    // it from a locked device. The native report states its declared policy and
    // the live lock state.
    final native = await AppIntentBridge.invokeSensitiveIntent();
    if (native != null && native.isNotEmpty) {
      await DvmaEvidence.record(
        LockscreenControlActionAuthorizationScreen.vulnId,
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
      vulnId: LockscreenControlActionAuthorizationScreen.vulnId,
      title: 'Lock-Screen Control / Widget Action Authorization',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'A WidgetKit Control / interactive widget on the Lock Screen, '
          'Control Center, or Action Button can invoke an App Intent. If a '
          'sensitive intent (unlock the front door, disable the alarm) runs '
          'without the authentication the full app would require, a '
          'physically-present attacker triggers a privileged operation from a '
          'LOCKED device. The system surface offering the control is not the '
          "app's auth gate. On iOS this is backed by a REAL App Intent "
          '(UnlockFrontDoorIntent) shipped in the app binary that declares no '
          'authentication policy, so the system runs it from a locked device; '
          'off-iOS it uses a deterministic model. The '
          'secure path requires unlock / biometric for sensitive intents '
          'regardless of surface, deferring until authenticated while still '
          'allowing non-sensitive intents like a flashlight toggle.',
      children: [
        DemoActionButton(
          label: 'Invoke unlockFrontDoor from lock screen',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'sensitive intent ran from locked device, no auth',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'secure: deferred until authenticated',
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
