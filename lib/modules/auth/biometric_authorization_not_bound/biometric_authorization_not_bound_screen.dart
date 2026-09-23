import 'package:flutter/material.dart';

import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../passkey_ceremony.dart';
import 'biometric_authorizer.dart';

/// Biometric Authorization Not Bound to Operation.
///
/// The biometric prompt returns a boolean success not cryptographically bound
/// to the operation, so a success captured for one operation is replayed onto
/// a different sensitive operation (Android BiometricPrompt CVE-2025-48528
/// class).
class BiometricAuthorizationNotBoundScreen extends StatefulWidget {
  const BiometricAuthorizationNotBoundScreen({super.key});

  static const String vulnId = 'biometric_authorization_not_bound';

  @override
  State<BiometricAuthorizationNotBoundScreen> createState() =>
      _BiometricAuthorizationNotBoundScreenState();
}

class _BiometricAuthorizationNotBoundScreenState
    extends State<BiometricAuthorizationNotBoundScreen> {
  String? _vulnResult;
  String? _secureResult;
  String? _prefsKey;

  String _render(AuthToken token, AuthorizationResult r) {
    final b = StringBuffer();
    b.writeln('token bound to op  : ${token.boundOperationId ?? '(unbound)'}');
    b.writeln('token signature    : ${token.signature ?? '(none)'}');
    b.writeln('authorizing op     : ${r.operationId}');
    b.writeln('authorized         : ${r.authorized}');
    b.writeln('replayed onto op B : ${r.replayed}');
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  void _run() {
    final auth = BiometricAuthorizer();

    // The user authorizes the low-value "view balance" operation.
    final vulnToken = auth.authorize(
      BiometricAuthorizer.operationView,
      promptSuccess: true,
    );
    // VULN: that unbound success token is replayed onto the wire transfer.
    final vuln = auth.useToken(
      BiometricAuthorizer.operationTransfer,
      vulnToken,
    );

    // SECURE: the token is signed for "view balance" only.
    final secureToken = auth.authorizeSafe(
      BiometricAuthorizer.operationView,
      promptSuccess: true,
    );
    // SECURE: replaying it onto the transfer fails the signature check.
    final secure = auth.useTokenSafe(
      BiometricAuthorizer.operationTransfer,
      secureToken,
    );

    // VULN: persist the unbound token + successful cross-operation replay to
    // real SharedPreferences. The recoverable artifact is a reusable biometric
    // success carrying no operation identity, authorizing a different op.
    if (vuln.authorized && vuln.replayed) {
      // Fire-and-forget persistence; UI updates immediately from the sync path.
      PasskeyEvidenceStore.persist(
        vulnId: BiometricAuthorizationNotBoundScreen.vulnId,
        kind: 'unbound-token',
        keySuffix: 'replayed_token',
        value:
            'boundOp=${vulnToken.boundOperationId ?? "(unbound)"} '
            'success=${vulnToken.success} '
            'replayedOnto=${vuln.operationId} authorized=${vuln.authorized}',
      ).then((prefsKey) {
        if (!mounted) return;
        setState(() {
          _prefsKey = prefsKey;
          _vulnResult =
              '${_render(vulnToken, vuln)}\n'
              'persisted to prefs key: $prefsKey';
        });
      });
    }

    setState(() {
      _vulnResult = _render(vulnToken, vuln);
      _secureResult = _render(secureToken, secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: BiometricAuthorizationNotBoundScreen.vulnId,
      title: 'Biometric Authorization Not Bound to Operation',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The biometric prompt returns a bare boolean "success" that is NOT '
          'cryptographically bound to the operation being authorized (no '
          'CryptoObject / no signed server challenge). A success the user gave '
          'for a low-value operation (view balance) is therefore REPLAYED to '
          'authorize a different sensitive operation (a wire transfer); an '
          'overlaid prompt lets an attacker capture/redirect the result '
          '(Android BiometricPrompt CVE-2025-48528 class). This is an offline, '
          'deterministic simulation. The secure path binds the biometric '
          'result to a per-operation signed challenge, so the token only '
          'authorizes the exact operation it was minted for.',
      children: [
        DemoActionButton(
          label: 'Replay "view" success onto transfer',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'unbound boolean success replayed',
            value: _vulnResult!,
          ),
        if (_prefsKey != null)
          DeviceArtifactPanel(
            storeKey: _prefsKey!,
            describes:
                'the unbound biometric success token replayed onto the '
                'transfer',
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'per-operation signed challenge',
            value: _secureResult!,
          ),
      ],
    );
  }
}
