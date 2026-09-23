import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'backdoor_auth.dart';

/// Developer Backdoor.
///
/// A hidden hardcoded backdoor credential / debug route grants privileged
/// access.
class DeveloperBackdoorScreen extends StatefulWidget {
  const DeveloperBackdoorScreen({super.key});

  static const String vulnId = 'developer_backdoor';

  @override
  State<DeveloperBackdoorScreen> createState() =>
      _DeveloperBackdoorScreenState();
}

class _DeveloperBackdoorScreenState extends State<DeveloperBackdoorScreen> {
  final _user = TextEditingController(text: BackdoorAuth.backdoorUser);
  final _password = TextEditingController(text: BackdoorAuth.backdoorPassword);
  String? _vulnResult;
  String? _secureResult;

  void _run() {
    final vuln = BackdoorAuth.authenticate(_user.text, _password.text);
    final secure = BackdoorAuth.secureAuthenticate(_user.text, _password.text);
    if (vuln.success && vuln.via == 'backdoor') {
      // Real leak: the hardcoded master backdoor credential granted admin.
      DvmaEvidence.record(
        DeveloperBackdoorScreen.vulnId,
        'backdoor',
        'backdoor login granted admin: '
            '${BackdoorAuth.backdoorUser} / ${BackdoorAuth.backdoorPassword} '
            '(admin=${vuln.isAdmin}, via=${vuln.via})',
      );
    }
    setState(() {
      _vulnResult = vuln.success
          ? 'ACCESS GRANTED (admin=${vuln.isAdmin}, via=${vuln.via})'
          : 'denied';
      _secureResult = secure.success
          ? 'granted (admin=${secure.isAdmin}, via=${secure.via})'
          : 'denied (no backdoor account exists)';
    });
  }

  @override
  Widget build(BuildContext context) {
    final lingo = PlatformLingo.current();
    return VulnDemoScaffold(
      vulnId: DeveloperBackdoorScreen.vulnId,
      title: 'Developer Backdoor',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'Alongside normal login, the authenticator special-cases a hidden, '
          'hardcoded "dev_backdoor" master credential that immediately grants '
          'admin. Anyone who reads the binary with ${lingo.reverseTools} '
          'recovers the credential and bypasses all authentication. Production '
          'builds must never ship debug/master backdoors.',
      children: [
        TextField(
          controller: _user,
          decoration: const InputDecoration(labelText: 'Username'),
        ),
        const SizedBox(height: DvmaSpacing.sm),
        TextField(
          controller: _password,
          decoration: const InputDecoration(labelText: 'Password'),
        ),
        DemoActionButton(label: 'Log in', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(label: 'vulnerable authenticator', value: _vulnResult!),
        if (_secureResult != null)
          EvidencePanel(
            label: 'authenticator without a backdoor',
            value: _secureResult!,
          ),
      ],
    );
  }
}
