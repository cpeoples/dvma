import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'sensitive_logger.dart';

/// Sensitive Data in Logs.
///
/// PII, tokens, and passwords printed to system logs.
class SensitiveDataInLogsScreen extends StatefulWidget {
  const SensitiveDataInLogsScreen({super.key});

  static const String vulnId = 'sensitive_data_in_logs';

  @override
  State<SensitiveDataInLogsScreen> createState() =>
      _SensitiveDataInLogsScreenState();
}

class _SensitiveDataInLogsScreenState extends State<SensitiveDataInLogsScreen> {
  final _logger = SensitiveLogger();
  final _user = TextEditingController(text: 'alice@corp.example');
  final _pass = TextEditingController(text: 'Sup3rSecret!');
  String? _line;
  bool _sending = false;

  Future<void> _login() async {
    setState(() {
      _sending = true;
      _line = null;
    });

    // VULN: the login handler writes the username, plaintext password, and auth
    // token straight to the system log (developer.log -> Logcat). Anyone with
    // `adb logcat`, idevicesyslog, or READ_LOGS can harvest credentials.
    final line = _logger.logLogin(
      username: _user.text,
      password: _pass.text,
      token: 'eyJhbGciOiJIUzI1NiJ9.session',
    );

    // Mirror the real leaked log line to the evidence sink (logcat + artifact).
    await DvmaEvidence.record(
      SensitiveDataInLogsScreen.vulnId,
      'log-leak',
      line,
    );

    if (!mounted) return;
    setState(() {
      _sending = false;
      _line = line;
    });
  }

  @override
  Widget build(BuildContext context) {
    final lingo = PlatformLingo.current();
    return VulnDemoScaffold(
      vulnId: SensitiveDataInLogsScreen.vulnId,
      title: 'Sensitive Data in Logs',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'The login handler writes the username, plaintext password, and auth '
          'token straight to the system log (developer.log → ${lingo.logSink}). '
          'This emits a log line - anyone with ${lingo.logReadTool} can harvest '
          'credentials with zero effort.',
      children: [
        TextField(
          controller: _user,
          decoration: const InputDecoration(labelText: 'Username'),
        ),
        const SizedBox(height: DvmaSpacing.sm),
        TextField(
          controller: _pass,
          decoration: const InputDecoration(labelText: 'Password'),
        ),
        DemoActionButton(
          label: _sending
              ? 'Logging in…'
              : 'Log in (writes to ${lingo.logSink})',
          onPressed: _sending ? () {} : () => _login(),
        ),
        if (_line != null)
          EvidencePanel(label: 'emitted to system log', value: _line!),
      ],
    );
  }
}
