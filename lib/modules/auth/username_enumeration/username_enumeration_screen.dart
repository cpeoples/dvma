import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'enumerable_auth.dart';

/// Username Enumeration.
///
/// Login returns distinguishable responses for valid vs invalid usernames,
/// allowing account enumeration.
class UsernameEnumerationScreen extends StatefulWidget {
  const UsernameEnumerationScreen({super.key});

  static const String vulnId = 'username_enumeration';

  @override
  State<UsernameEnumerationScreen> createState() =>
      _UsernameEnumerationScreenState();
}

class _UsernameEnumerationScreenState extends State<UsernameEnumerationScreen> {
  String? _vulnResult;
  String? _secureResult;

  void _run() {
    // Same wrong password against a real account vs an unknown account.
    final knownUser = EnumerableAuth.authenticate('alice', 'wrong-password');
    final unknownUser = EnumerableAuth.authenticate(
      'mallory',
      'wrong-password',
    );

    final secureKnown = EnumerableAuth.secureAuthenticate(
      'alice',
      'wrong-password',
    );
    final secureUnknown = EnumerableAuth.secureAuthenticate(
      'mallory',
      'wrong-password',
    );

    setState(() {
      _vulnResult =
          'alice (real acct):   ${knownUser.message}\n'
          'mallory (unknown):   ${unknownUser.message}\n'
          '=> responses differ, so accounts are enumerable';
      _secureResult =
          'alice (real acct):   ${secureKnown.message}\n'
          'mallory (unknown):   ${secureUnknown.message}\n'
          '=> identical generic error';
    });

    // Real leak: the two distinguishable responses ARE the enumeration oracle.
    DvmaEvidence.record(
      UsernameEnumerationScreen.vulnId,
      'user-enum',
      'alice(real,wrong-pw)="${knownUser.message}" '
          'mallory(unknown)="${unknownUser.message}" '
          '=> distinguishable responses reveal valid accounts',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: UsernameEnumerationScreen.vulnId,
      title: 'Username Enumeration',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'The login helper returns "No such user" for an unknown account but '
          '"Invalid password" for a real account with the wrong password. By '
          'observing which error comes back, an attacker enumerates valid '
          'usernames without knowing any password. A secure login returns a '
          'single generic error for every failure.',
      children: [
        DemoActionButton(
          label: 'Probe a real vs unknown account',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'vulnerable login responses',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'what a secure login returns',
            value: _secureResult!,
          ),
      ],
    );
  }
}
