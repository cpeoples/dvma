import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../jwt_vulnerabilities/insecure_jwt.dart';

/// OAuth Misconfiguration (implicit flow token leakage).
///
/// Implicit-flow access token leaks via redirect URL and logs.
class OauthMisconfigurationScreen extends StatefulWidget {
  const OauthMisconfigurationScreen({super.key});

  static const String vulnId = 'oauth_misconfiguration';

  @override
  State<OauthMisconfigurationScreen> createState() =>
      _OauthMisconfigurationScreenState();
}

class _OauthMisconfigurationScreenState
    extends State<OauthMisconfigurationScreen> {
  String? _redirect;
  String? _logged;

  void _authorize() {
    // VULN: legacy OAuth *implicit* flow returns the access token directly in
    // the redirect URL fragment (response_type=token). It lands in browser
    // history, Referer headers, and, as below, the app logs it verbatim.
    //
    // The token is a real HS256 bearer JWT minted via the app's insecure JWT
    // path (weak, guessable secret), so a pentester who captures it from the
    // redirect/log can decode its claims and, because the signing secret is
    // weak, forge an elevated token, not just eyeball an opaque string.
    final token = InsecureJwt.signWeak({
      'sub': 'user-8842',
      'scope': 'profile email transactions.read',
      'role': 'user',
      'iss': 'https://auth.dvma.example',
      'aud': 'dvma-mobile',
      'exp': 9999999999,
    });
    final redirect =
        'dvma://callback#access_token=$token&token_type=bearer&expires_in=3600';
    // Also leaked to the harness's collectable sink (reaches logcat + a
    // pullable artifact file, unlike dart:developer.log which does not).
    DvmaEvidence.record(
      OauthMisconfigurationScreen.vulnId,
      'oauth-token',
      'OAuth redirect: $redirect',
    );
    setState(() {
      _redirect = redirect;
      _logged = 'DvmaEvidence.record("OAuth redirect: ...$token...")';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: OauthMisconfigurationScreen.vulnId,
      title: 'OAuth Misconfiguration',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The app uses the deprecated OAuth implicit flow '
          '(response_type=token), so the access token is returned in the '
          'redirect URL fragment - exposed to browser history, Referer '
          'headers, and (here) the app logs. The leaked token is a REAL HS256 '
          'JWT signed with a weak secret, so a captured token can be decoded '
          'and re-forged with elevated claims. Modern apps use auth-code + '
          'PKCE and never put tokens in URLs.',
      children: [
        DemoActionButton(
          label: 'Authorize (implicit flow)',
          onPressed: _authorize,
        ),
        if (_redirect != null)
          EvidencePanel(
            label: 'redirect URL (token in fragment)',
            value: _redirect!,
          ),
        if (_logged != null)
          EvidencePanel(label: 'also leaked to logs', value: _logged!),
      ],
    );
  }
}
