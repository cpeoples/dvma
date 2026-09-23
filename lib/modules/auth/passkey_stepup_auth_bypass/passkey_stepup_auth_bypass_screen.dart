import 'package:flutter/material.dart';

import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../passkey_ceremony.dart';
import 'stepup_flow.dart';

/// Passkey Step-Up Authentication Bypass.
///
/// A sensitive action's "step-up verified" flag is set from the mere existence
/// of a registered passkey instead of a completed assertion (New-API AI gateway
/// CVE-2026-32879 class).
class PasskeyStepupAuthBypassScreen extends StatefulWidget {
  const PasskeyStepupAuthBypassScreen({super.key});

  static const String vulnId = 'passkey_stepup_auth_bypass';

  @override
  State<PasskeyStepupAuthBypassScreen> createState() =>
      _PasskeyStepupAuthBypassScreenState();
}

class _PasskeyStepupAuthBypassScreenState
    extends State<PasskeyStepupAuthBypassScreen> {
  // Default attack: a passkey is registered, but no fresh assertion completed.
  bool _hasRegisteredPasskey = true;
  bool _freshAssertionCompleted = false;
  String? _vulnResult;
  String? _secureResult;
  String? _prefsKey;

  Future<void> _run() async {
    final vuln = StepUpFlow.attemptSensitiveAction(
      hasRegisteredPasskey: _hasRegisteredPasskey,
      freshAssertionCompleted: _freshAssertionCompleted,
    );
    // Secure flow: issue a step-up challenge; a fresh assertion must sign it.
    const issued = 'stepup-chal-42';
    final asserted = _freshAssertionCompleted ? issued : '';
    final secure = StepUpFlow.secureAttemptSensitiveAction(
      hasRegisteredPasskey: _hasRegisteredPasskey,
      freshAssertionCompleted: _freshAssertionCompleted,
      issuedChallenge: issued,
      assertedChallenge: asserted,
    );

    String? prefsKey;
    // VULN: when the sensitive action is allowed WITHOUT a fresh assertion,
    // persist that "step-up satisfied" grant to real SharedPreferences. The
    // recoverable artifact is a stored authorization created with no re-auth.
    if (vuln.actionAllowed && !_freshAssertionCompleted) {
      prefsKey = await PasskeyEvidenceStore.persist(
        vulnId: PasskeyStepupAuthBypassScreen.vulnId,
        kind: 'stepup-bypass',
        keySuffix: 'stepup_granted',
        value:
            'action=wire-transfer allowed=true '
            'freshAssertion=$_freshAssertionCompleted '
            'hasPasskey=$_hasRegisteredPasskey',
      );
    }
    if (!mounted) return;

    setState(() {
      _prefsKey = prefsKey;
      _vulnResult =
          'hasPasskey=$_hasRegisteredPasskey '
          'freshAssertion=$_freshAssertionCompleted -> '
          'verified=${vuln.verified} '
          'action=${vuln.actionAllowed ? "ALLOWED" : "blocked"}';
      _secureResult =
          'freshAssertion=$_freshAssertionCompleted -> '
          'verified=${secure.verified} '
          'action=${secure.actionAllowed ? "allowed" : "blocked"}';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PasskeyStepupAuthBypassScreen.vulnId,
      title: 'Passkey Step-Up Bypass',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The sensitive action clears its "step-up verified" gate because the '
          'account merely has a passkey registered - no fresh assertion is '
          'required. A correct flow issues a step-up challenge and requires a '
          'fresh assertion that signs exactly that challenge.'
          ' ${PasskeyCeremony.scopeNote}',
      children: [
        SwitchListTile(
          value: _hasRegisteredPasskey,
          onChanged: (v) => setState(() => _hasRegisteredPasskey = v),
          title: const Text('Account has a registered passkey'),
          contentPadding: EdgeInsets.zero,
        ),
        SwitchListTile(
          value: _freshAssertionCompleted,
          onChanged: (v) => setState(() => _freshAssertionCompleted = v),
          title: const Text('Fresh step-up assertion completed'),
          subtitle: const Text('attack: leave OFF'),
          contentPadding: EdgeInsets.zero,
        ),
        DemoActionButton(label: 'Perform sensitive action', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'vulnerable flow (existence == verified)',
            value: _vulnResult!,
          ),
        if (_prefsKey != null)
          DeviceArtifactPanel(
            storeKey: _prefsKey!,
            describes:
                'the sensitive action grant created without a fresh '
                'assertion',
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'secure flow (fresh assertion required)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
