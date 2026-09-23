import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'credential_provider_service.dart';

/// Credential-Provider Release Authorization.
///
/// A credential-provider / password-manager extension releases a stored
/// credential without validating the calling app / relying-party identity or
/// the user-verification state.
class CredentialProviderReleaseAuthorizationScreen extends StatefulWidget {
  const CredentialProviderReleaseAuthorizationScreen({super.key});

  static const String vulnId = 'credential_provider_release_authorization';

  @override
  State<CredentialProviderReleaseAuthorizationScreen> createState() =>
      _CredentialProviderReleaseAuthorizationScreenState();
}

class _CredentialProviderReleaseAuthorizationScreenState
    extends State<CredentialProviderReleaseAuthorizationScreen> {
  String? _vulnResult;
  String? _secureResult;

  String _render(ReleaseResult r, {List<String>? enumerated}) {
    final b = StringBuffer();
    b.writeln('rpId               : ${r.rpId}');
    b.writeln('calling app        : ${r.callingApp}');
    b.writeln('bound app (rpId)   : ${CredentialProviderService.legitApp}');
    b.writeln('released           : ${r.released}');
    b.writeln('secret             : ${r.secret ?? '(none)'}');
    b.writeln('spoofed release    : ${r.spoofedRelease}');
    if (enumerated != null) {
      b.writeln('enumerable rpIds   : ${enumerated.join(', ')}');
    }
    if (r.denyReason != null) {
      b.writeln('deny reason        : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    final service = CredentialProviderService.seeded();

    // VULN: a spoofed calling app requests the bank credential without UV and
    // gets it, and can enumerate every stored rpId.
    final vuln = service.getCredential(
      CredentialProviderService.bankRpId,
      CredentialProviderService.spoofedApp,
      userVerified: false,
    );
    final enumerated = service.enumerateRpIds();

    // SECURE: the calling app is not bound to the rpId -> refused.
    final secure = service.getCredentialSafe(
      CredentialProviderService.bankRpId,
      CredentialProviderService.spoofedApp,
      userVerified: false,
    );

    // real artifact: record the bank secret released to a spoofed app plus the
    // enumerable list of stored relying parties.
    await DvmaEvidence.record(
      CredentialProviderReleaseAuthorizationScreen.vulnId,
      'credential-release',
      'spoofed app=${vuln.callingApp} obtained rpId=${vuln.rpId} '
          'secret=${vuln.secret} (released=${vuln.released}, no UV); '
          'enumerable rpIds=${enumerated.join(",")}',
    );
    if (!mounted) return;
    setState(() {
      _vulnResult = _render(vuln, enumerated: enumerated);
      _secureResult = _render(secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: CredentialProviderReleaseAuthorizationScreen.vulnId,
      title: 'Credential-Provider Release Authorization',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A credential-provider / password-manager extension releases a '
          'stored credential / passkey assertion WITHOUT validating the '
          'calling app identity, the relying-party (rpId) binding, or the '
          'user-verification state. A spoofed calling app therefore extracts '
          'the bank credential (rpId/calling-app mismatch, no UV), and the API '
          'even lets any caller enumerate the stored relying parties '
          '(credential-provider release-boundary class). This is an offline, '
          'deterministic simulation. The secure path validates the calling app '
          'is bound to the rpId (asset-links / associated-domains style), '
          'requires user verification, and refuses enumeration.',
      children: [
        DemoActionButton(
          label: 'Request bank credential as spoofed app',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'released on mismatch, no UV, enumerable',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'calling-app binding + UV enforced',
            value: _secureResult!,
          ),
      ],
    );
  }
}
