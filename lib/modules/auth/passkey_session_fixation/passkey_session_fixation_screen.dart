import 'package:flutter/material.dart';

import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../passkey_ceremony.dart';
import 'session_fixation_flow.dart';

/// Session Fixation After WebAuthn Assertion.
///
/// The session identifier is not rotated after a successful passkey assertion,
/// so a pre-set (attacker-known) session id remains valid post-login.
class PasskeySessionFixationScreen extends StatefulWidget {
  const PasskeySessionFixationScreen({super.key});

  static const String vulnId = 'passkey_session_fixation';

  @override
  State<PasskeySessionFixationScreen> createState() =>
      _PasskeySessionFixationScreenState();
}

class _PasskeySessionFixationScreenState
    extends State<PasskeySessionFixationScreen> {
  // Attacker-planted, pre-auth session id known to the attacker.
  final _preAuthId = TextEditingController(text: 'ATTACKER-FIXED-SESSION-1234');
  String? _vulnResult;
  String? _secureResult;
  String? _prefsKey;

  Future<void> _run() async {
    final attackerKnownId = _preAuthId.text;
    final vuln = SessionFixationFlow.login(
      preAuthSessionId: attackerKnownId,
      assertionValid: true,
    );
    final secure = SessionFixationFlow.secureLogin(
      preAuthSessionId: attackerKnownId,
      assertionValid: true,
    );
    final vulnHijack = vuln.authenticated && vuln.sessionId == attackerKnownId;
    final secureHijack =
        secure.authenticated && secure.sessionId == attackerKnownId;

    // VULN: persist the NON-rotated (attacker-known) session id to real
    // SharedPreferences as the authenticated session. The recoverable artifact
    // is a live session id equal to the pre-auth id an attacker planted.
    final prefsKey = await PasskeyEvidenceStore.persist(
      vulnId: PasskeySessionFixationScreen.vulnId,
      kind: 'session-fixation',
      keySuffix: 'authenticated_session',
      value: vuln.sessionId,
    );
    if (!mounted) return;

    setState(() {
      _prefsKey = prefsKey;
      _vulnResult =
          'authed=${vuln.authenticated} rotated=${vuln.rotated}\n'
          'session=${vuln.sessionId}\n'
          'attacker-known id still valid=${vulnHijack ? "YES (hijack)" : "no"}\n'
          'persisted to prefs key: $prefsKey';
      _secureResult =
          'authed=${secure.authenticated} rotated=${secure.rotated}\n'
          'session=${secure.sessionId}\n'
          'attacker-known id still valid=${secureHijack ? "yes" : "no"}';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PasskeySessionFixationScreen.vulnId,
      title: 'Passkey Session Fixation',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The session id set before login is kept unchanged after a successful '
          'passkey assertion. An attacker who planted that pre-auth id still '
          'knows it afterward, so their copy is now an authenticated session. A '
          'correct flow rotates the session id on authentication.'
          ' ${PasskeyCeremony.scopeNote}',
      children: [
        TextField(
          controller: _preAuthId,
          decoration: const InputDecoration(
            labelText: 'Pre-auth (attacker-known) id',
          ),
        ),
        DemoActionButton(label: 'Authenticate with passkey', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'vulnerable flow (no rotation)',
            value: _vulnResult!,
          ),
        if (_prefsKey != null)
          DeviceArtifactPanel(
            storeKey: _prefsKey!,
            describes:
                'the authenticated session id - identical to the '
                'attacker-planted pre-auth id',
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'secure flow (rotates session id)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
