import 'package:flutter/material.dart';

import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../passkey_ceremony.dart';
import 'challenge_server.dart';

/// Passkey Challenge Reuse / Not Bound.
///
/// The server challenge is static / reused / never bound to a single ceremony,
/// so a recorded assertion for one challenge is accepted again.
class PasskeyChallengeReuseScreen extends StatefulWidget {
  const PasskeyChallengeReuseScreen({super.key});

  static const String vulnId = 'passkey_challenge_reuse';

  @override
  State<PasskeyChallengeReuseScreen> createState() =>
      _PasskeyChallengeReuseScreenState();
}

class _PasskeyChallengeReuseScreenState
    extends State<PasskeyChallengeReuseScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _prefsKey;

  PasskeyAssertion get _recordedAssertion => PasskeyCeremony.assertion(
    credentialId: 'cred-victim',
    rpId: 'dvma.training',
    origin: 'https://dvma.training',
  );

  Future<void> _run() async {
    // Vulnerable server: attacker records the assertion for the static
    // challenge, then replays it. Both attempts succeed.
    final vuln = ReusedChallengeServer();
    final vulnChallenge = vuln.issueChallenge();
    final vulnFirst = vuln.verifyAssertion(
      _recordedAssertion,
      challenge: vulnChallenge,
    );
    // Replay: same recorded assertion + same (static) challenge.
    final vulnReplay = vuln.verifyAssertion(
      _recordedAssertion,
      challenge: vulnChallenge,
    );

    // VULN: persist the reused/static challenge to real SharedPreferences so a
    // trainee can recover it off-device (adb/objection) and replay assertions.
    final prefsKey = await PasskeyEvidenceStore.persist(
      vulnId: PasskeyChallengeReuseScreen.vulnId,
      kind: 'passkey-challenge',
      keySuffix: 'reused_challenge',
      value: vulnChallenge,
    );
    if (!mounted) return;

    // Secure server: challenge is single-use; the replay of the first
    // challenge is rejected because it was consumed.
    final secure = SecureChallengeServer();
    final secureChallenge = secure.issueChallenge();
    final secureFirst = secure.verifyAssertion(
      _recordedAssertion,
      challenge: secureChallenge,
    );
    final secureReplay = secure.verifyAssertion(
      _recordedAssertion,
      challenge: secureChallenge,
    );

    setState(() {
      _prefsKey = prefsKey;
      _vulnResult =
          'challenge=$vulnChallenge\n'
          'first=${vulnFirst ? "ACCEPTED" : "rejected"} '
          'replay=${vulnReplay ? "ACCEPTED" : "rejected"}\n'
          'persisted to prefs key: $prefsKey';
      _secureResult =
          'first=${secureFirst ? "accepted" : "rejected"} '
          'replay=${secureReplay ? "accepted" : "rejected"} '
          '(challenge consumed once)';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PasskeyChallengeReuseScreen.vulnId,
      title: 'Passkey Challenge Reuse',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The server hands out a fixed challenge and never invalidates it '
          'after use, so a recorded assertion that signs over that challenge '
          'is accepted again on replay. A correct server issues a unique, '
          'single-use challenge per ceremony and consumes it on first verify.'
          ' ${PasskeyCeremony.scopeNote}',
      children: [
        DemoActionButton(
          label: 'Submit then replay assertion',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'vulnerable server (static)',
            value: _vulnResult!,
          ),
        if (_prefsKey != null)
          DeviceArtifactPanel(
            storeKey: _prefsKey!,
            verb: 'now holds',
            describes: 'the reused challenge',
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'secure server (one-time challenge)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
