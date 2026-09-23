import 'package:flutter/material.dart';

import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../passkey_ceremony.dart';
import 'signcount_verifier.dart';

/// Passkey Assertion Replay (Sign-Count Not Enforced).
///
/// The authenticator sign-count is never persisted or compared, so a captured
/// WebAuthn assertion replays to create additional authenticated sessions
/// (Craft CMS CVE-2026-72780 class).
class PasskeyAssertionReplaySigncountScreen extends StatefulWidget {
  const PasskeyAssertionReplaySigncountScreen({super.key});

  static const String vulnId = 'passkey_assertion_replay_signcount';

  @override
  State<PasskeyAssertionReplaySigncountScreen> createState() =>
      _PasskeyAssertionReplaySigncountScreenState();
}

class _PasskeyAssertionReplaySigncountScreenState
    extends State<PasskeyAssertionReplaySigncountScreen> {
  // The attacker replays a single captured assertion whose sign-count stays 5.
  int _replayCount = 3;
  String? _vulnResult;
  String? _secureResult;
  String? _prefsKey;

  PasskeyAssertion get _capturedAssertion => PasskeyCeremony.assertion(
    credentialId: 'cred-victim',
    rpId: 'dvma.training',
    origin: 'https://dvma.training',
  );

  Future<void> _run() async {
    // The captured assertion always reports the SAME sign-count (5): a replay.
    const capturedSignCount = 5;
    final vuln = SignCountVerifier();
    final secure = SecureSignCountVerifier();
    var vulnAccepted = 0;
    var secureAccepted = 0;
    for (var i = 0; i < _replayCount; i++) {
      if (vuln.verify(
        _capturedAssertion,
        reportedSignCount: capturedSignCount,
      )) {
        vulnAccepted++;
      }
      if (secure.verify(
        _capturedAssertion,
        reportedSignCount: capturedSignCount,
      )) {
        secureAccepted++;
      }
    }

    // VULN: persist the (never-advanced) sign-count to real SharedPreferences.
    // The recoverable artifact is a stored counter that stays at 5 even though
    // multiple sessions were minted - proof the replay was never detected.
    final prior = await PasskeyEvidenceStore.read(
      '${_capturedAssertion.credentialId}_signcount',
    );
    final prefsKey = await PasskeyEvidenceStore.persist(
      vulnId: PasskeyAssertionReplaySigncountScreen.vulnId,
      kind: 'signcount',
      keySuffix: '${_capturedAssertion.credentialId}_signcount',
      value: capturedSignCount.toString(),
    );
    if (!mounted) return;

    setState(() {
      _prefsKey = prefsKey;
      _vulnResult =
          'replays=$_replayCount accepted=$vulnAccepted '
          'sessions=${vuln.issuedSessions.length} '
          '(counter never compared)\n'
          'persisted signcount=$capturedSignCount '
          '(prior stored=${prior ?? "none"}) -> never advanced';
      _secureResult =
          'replays=$_replayCount accepted=$secureAccepted '
          'sessions=${secure.issuedSessions.length} '
          '(non-increasing counter rejected)';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PasskeyAssertionReplaySigncountScreen.vulnId,
      title: 'Passkey Assertion Replay (Sign-Count)',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The relying party never persists or compares the authenticator '
          'signature counter. A single captured assertion (sign-count = 5) is '
          'replayed to mint several authenticated sessions. A correct verifier '
          'stores the last counter and rejects any assertion that does not '
          'strictly advance it.'
          ' ${PasskeyCeremony.scopeNote}',
      children: [
        // Isolate the Slider's adjustable semantics so it can't absorb the
        // sibling action button's `demo_action_*` node on iOS (the XCUITest
        // walk found 0 actions on slider screens without this boundary).
        Semantics(
          container: true,
          explicitChildNodes: true,
          child: Row(
            children: [
              const Text('Replay attempts'),
              Expanded(
                child: Slider(
                  min: 1,
                  max: 8,
                  divisions: 7,
                  value: _replayCount.toDouble(),
                  label: '$_replayCount',
                  onChanged: (v) => setState(() => _replayCount = v.round()),
                ),
              ),
              Text('$_replayCount'),
            ],
          ),
        ),
        DemoActionButton(label: 'Replay captured assertion', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'vulnerable RP (no counter)',
            value: _vulnResult!,
          ),
        if (_prefsKey != null)
          DeviceArtifactPanel(
            storeKey: _prefsKey!,
            describes:
                'the stored sign-count that never advances across '
                'replays',
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'secure RP (counter enforced)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
