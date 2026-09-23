import 'package:flutter/material.dart';

import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../passkey_ceremony.dart';
import 'uv_verifier.dart';

/// Passkey User-Verification (UV) Enforcement Bypass.
///
/// A configured userVerification=REQUIRED is silently not enforced, so
/// assertions with the UV flag unset (presence-only) are accepted
/// (Spring Security CVE-2026-47841 class).
class PasskeyUserVerificationBypassScreen extends StatefulWidget {
  const PasskeyUserVerificationBypassScreen({super.key});

  static const String vulnId = 'passkey_user_verification_bypass';

  @override
  State<PasskeyUserVerificationBypassScreen> createState() =>
      _PasskeyUserVerificationBypassScreenState();
}

class _PasskeyUserVerificationBypassScreenState
    extends State<PasskeyUserVerificationBypassScreen> {
  // Default to the attack: user present (a tap) but not verified (no biometric).
  bool _userPresent = true;
  bool _userVerified = false;
  String? _vulnResult;
  String? _secureResult;
  String? _prefsKey;

  Future<void> _run() async {
    final vuln = UvVerifier.verify(
      signatureValid: true,
      userPresent: _userPresent,
      userVerified: _userVerified,
    );
    final secure = UvVerifier.secureVerify(
      signatureValid: true,
      userPresent: _userPresent,
      userVerified: _userVerified,
    );

    String? prefsKey;
    // VULN: when the vulnerable verifier accepts a presence-only (UV=false)
    // assertion despite policy=required, persist that accepted credential to
    // real SharedPreferences as the recoverable artifact.
    if (vuln && !_userVerified) {
      prefsKey = await PasskeyEvidenceStore.persist(
        vulnId: PasskeyUserVerificationBypassScreen.vulnId,
        kind: 'uv-bypass',
        keySuffix: 'up_only_accepted',
        value:
            'policy=${UvVerifier.policy} UP=$_userPresent '
            'UV=$_userVerified accepted=true',
      );
    }
    if (!mounted) return;

    setState(() {
      _prefsKey = prefsKey;
      _vulnResult =
          'policy=${UvVerifier.policy} UP=$_userPresent '
          'UV=$_userVerified -> ${vuln ? "ACCEPTED" : "rejected"}';
      _secureResult =
          'policy=${UvVerifier.policy} UP=$_userPresent '
          'UV=$_userVerified -> ${secure ? "accepted" : "rejected"}';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PasskeyUserVerificationBypassScreen.vulnId,
      title: 'Passkey UV Enforcement Bypass',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The relying party requests userVerification=REQUIRED but only checks '
          'the User-Presence flag, ignoring the User-Verification flag. A '
          'presence-only assertion (a tap, no biometric/PIN) is therefore '
          'accepted. A correct verifier rejects UP-only assertions when the '
          'policy is REQUIRED.'
          ' ${PasskeyCeremony.scopeNote}',
      children: [
        SwitchListTile(
          value: _userPresent,
          onChanged: (v) => setState(() => _userPresent = v),
          title: const Text('User Present (UP) flag'),
          contentPadding: EdgeInsets.zero,
        ),
        SwitchListTile(
          value: _userVerified,
          onChanged: (v) => setState(() => _userVerified = v),
          title: const Text('User Verified (UV) flag'),
          subtitle: const Text('attack: leave OFF (presence-only)'),
          contentPadding: EdgeInsets.zero,
        ),
        DemoActionButton(label: 'Verify assertion', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'vulnerable verifier (UV ignored)',
            value: _vulnResult!,
          ),
        if (_prefsKey != null)
          DeviceArtifactPanel(
            storeKey: _prefsKey!,
            describes: 'the accepted presence-only (UV=false) credential',
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'secure verifier (UV enforced)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
