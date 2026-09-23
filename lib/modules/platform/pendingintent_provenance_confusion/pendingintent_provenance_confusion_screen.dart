import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'pending_intent_authenticator.dart';

/// PendingIntent Provenance Confusion.
///
/// A receiving SDK assumes 'who presents a PendingIntent' == 'who created it',
/// so a replayed/forwarded token authenticates an attacker as the creating app
/// (PendingIntent provenance-confusion research, arXiv 2603.02539).
class PendingintentProvenanceConfusionScreen extends StatefulWidget {
  const PendingintentProvenanceConfusionScreen({super.key});

  static const String vulnId = 'pendingintent_provenance_confusion';

  @override
  State<PendingintentProvenanceConfusionScreen> createState() =>
      _PendingintentProvenanceConfusionScreenState();
}

class _PendingintentProvenanceConfusionScreenState
    extends State<PendingintentProvenanceConfusionScreen> {
  // A token minted by the trusted app, now forwarded to / stolen by the evil
  // app which will present it.
  static const PendingIntentToken _forwardedToken = PendingIntentToken(
    creatorPackage: 'com.trusted.app',
  );
  static const String _presenter = 'com.evil.app';

  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  Future<void> _run() async {
    final vuln = PendingIntentAuthenticator.authenticate(
      _forwardedToken,
      _presenter,
    );
    final secure = PendingIntentAuthenticator.authenticateStrict(
      _forwardedToken,
      _presenter,
    );
    setState(() {
      _vulnResult =
          'presenter: $_presenter\n'
          'token.creatorPackage: ${_forwardedToken.creatorPackage}\n'
          'authenticated: ${vuln.authenticated}\n'
          'identity: ${vuln.identity}\n'
          'spoofed: ${vuln.spoofed}\n'
          '${vuln.reason}';
      _secureResult =
          'authenticated: ${secure.authenticated}\n'
          'identity: ${secure.identity}\n'
          '${secure.reason}';
    });

    // On-device: post the real mutable+implicit PendingIntent (the native
    // handler records under pendingintent_provenance_confusion too).
    final native = await PlatformIpcBridge.postMutablePendingIntent();
    if (!mounted) return;
    if (native != null && native.isNotEmpty) {
      await DvmaEvidence.record(
        PendingintentProvenanceConfusionScreen.vulnId,
        'mutable-pending-intent',
        native,
      );
      if (!mounted) return;
      setState(() => _nativeResult = native);
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PendingintentProvenanceConfusionScreen.vulnId,
      title: 'PendingIntent Provenance Confusion',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A PendingIntent is a capability that can be forwarded, stored and '
          'replayed. This SDK authenticates a caller by trusting what the TOKEN '
          'CLAIMS (its creatorPackage) instead of verifying who actually '
          'PRESENTS it. So a token minted by com.trusted.app, once forwarded to '
          'or stolen by com.evil.app, lets the attacker present it and be '
          'authenticated AS com.trusted.app - a confused-deputy / '
          'provenance-confusion flaw (arXiv 2603.02539). This is an offline, '
          'deterministic simulation: the token is a plain value and '
          'authentication returns the attributed identity. The strict '
          'authenticator binds the capability to its creator (and requires a '
          'non-replayable, immutable, single-use token), rejecting the mismatch.',
      children: [
        DemoActionButton(
          label: 'Present forwarded PendingIntent (as evil app)',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'claim-trusting SDK (authenticated attacker as trusted app)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'presenter-verifying SDK (rejects)',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'native mutable PendingIntent posted (device artifact)',
            value: _nativeResult!,
          ),
      ],
    );
  }
}
