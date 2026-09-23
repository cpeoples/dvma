import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'password_policy.dart';

/// Weak / No Password Policy.
///
/// Accepts single-character passwords; no complexity or length checks.
class WeakPasswordPolicyScreen extends StatefulWidget {
  const WeakPasswordPolicyScreen({super.key});

  static const String vulnId = 'weak_password_policy';

  @override
  State<WeakPasswordPolicyScreen> createState() =>
      _WeakPasswordPolicyScreenState();
}

class _WeakPasswordPolicyScreenState extends State<WeakPasswordPolicyScreen> {
  final _pw = TextEditingController(text: 'a');
  String? _result;

  void _register() {
    final ok = PasswordPolicy.isAcceptable(_pw.text);
    if (ok) {
      // Real leak: a trivially-weak password was accepted with no complexity
      // or length checks. Mirror the accepted value + its cosmetic label.
      DvmaEvidence.record(
        WeakPasswordPolicyScreen.vulnId,
        'weak-password',
        'accepted password="${_pw.text}" '
            '(${PasswordPolicy.strengthLabel(_pw.text)})',
      );
    }
    setState(
      () => _result = ok
          ? 'ACCEPTED ("${_pw.text}") - ${PasswordPolicy.strengthLabel(_pw.text)}'
          : 'rejected (empty)',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: WeakPasswordPolicyScreen.vulnId,
      title: 'Weak / No Password Policy',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'The registration form accepts any non-empty password - a single '
          'character, "123456", anything. There are no length, complexity, or '
          'breached-password checks, so accounts are trivially brute-forceable.',
      children: [
        TextField(
          controller: _pw,
          decoration: const InputDecoration(labelText: 'Choose a password'),
        ),
        DemoActionButton(label: 'Register', onPressed: _register),
        if (_result != null)
          EvidencePanel(label: 'policy decision', value: _result!),
      ],
    );
  }
}
