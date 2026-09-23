import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'insecure_jwt.dart';

/// JWT Vulnerabilities (alg:none, weak secret).
///
/// Accepts alg:none tokens and verifies with a weak, guessable secret.
class JwtVulnerabilitiesScreen extends StatefulWidget {
  const JwtVulnerabilitiesScreen({super.key});

  static const String vulnId = 'jwt_vulnerabilities';

  @override
  State<JwtVulnerabilitiesScreen> createState() =>
      _JwtVulnerabilitiesScreenState();
}

class _JwtVulnerabilitiesScreenState extends State<JwtVulnerabilitiesScreen> {
  String? _noneToken;
  String? _weakToken;
  String? _noneResult;
  String? _weakResult;

  void _run() {
    // Attacker forges an admin token with alg:none (no key needed).
    final none = InsecureJwt.forgeNoneToken({
      'sub': 'attacker',
      'role': 'admin',
    });
    // ...or one signed with the guessable 'secret'.
    final weak = InsecureJwt.signWeak({'sub': 'attacker', 'role': 'admin'});
    // Real leak: forged admin tokens the vulnerable verifier accepts (alg:none
    // needs no key; the HS256 one uses the guessable "secret").
    DvmaEvidence.record(
      JwtVulnerabilitiesScreen.vulnId,
      'jwt',
      'alg:none=$none weak-hmac=$weak',
    );
    setState(() {
      _noneToken = none;
      _weakToken = weak;
      _noneResult = InsecureJwt.verify(none)?.toString() ?? 'rejected';
      _weakResult = InsecureJwt.verify(weak)?.toString() ?? 'rejected';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: JwtVulnerabilitiesScreen.vulnId,
      title: 'JWT Vulnerabilities',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The token verifier accepts alg:none (no signature at all) and, when '
          'a signature is present, checks it with the weak secret "'
          '${InsecureJwt.weakSecret}". Either lets an attacker mint an '
          'admin token. Below, a forged attacker/admin token is accepted.',
      children: [
        DemoActionButton(label: 'Forge & verify admin tokens', onPressed: _run),
        if (_noneToken != null)
          EvidencePanel(label: 'forged alg:none token', value: _noneToken!),
        if (_noneResult != null)
          EvidencePanel(
            label: 'verify(none) => accepted claims',
            value: _noneResult!,
          ),
        if (_weakToken != null)
          EvidencePanel(label: 'weak-secret token', value: _weakToken!),
        if (_weakResult != null)
          EvidencePanel(
            label: 'verify(weak) => accepted claims',
            value: _weakResult!,
          ),
      ],
    );
  }
}
