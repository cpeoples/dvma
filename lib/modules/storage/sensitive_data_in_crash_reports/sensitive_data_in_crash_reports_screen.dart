import 'dart:developer' as developer;

import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'crash_reporter.dart';

/// Sensitive Data in Crash Reports.
///
/// On failure, the crash pipeline snapshots app state (auth token, password,
/// request body, breadcrumbs) and ships it to a third-party crash service. The
/// vulnerable path uploads the raw state; the secure path allowlists/redacts
/// before sending.
class SensitiveDataInCrashReportsScreen extends StatefulWidget {
  const SensitiveDataInCrashReportsScreen({super.key});

  static const String vulnId = 'sensitive_data_in_crash_reports';

  @override
  State<SensitiveDataInCrashReportsScreen> createState() =>
      _SensitiveDataInCrashReportsScreenState();
}

class _SensitiveDataInCrashReportsScreenState
    extends State<SensitiveDataInCrashReportsScreen> {
  String? _vulnResult;
  String? _secureResult;
  bool _sending = false;

  String _render(CrashReportResult r) {
    final b = StringBuffer();
    b.writeln('crash service      : ${CrashReporter.crashEndpoint}');
    b.writeln('sent               : ${r.sent}');
    b.writeln('scrubbed           : ${r.scrubbed}');
    b.writeln(
      'leaked fields      : ${r.leakedFields.isEmpty ? '(none)' : r.leakedFields.join(', ')}',
    );
    b.writeln('sensitive leaked   : ${r.leaked}');
    b.writeln('--- uploaded crash payload ---');
    b.writeln(r.payload);
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    setState(() {
      _sending = true;
      _vulnResult = null;
      _secureResult = null;
    });

    final state = CrashReporter.sampleState();

    // VULN: raw app state (secrets, PII, request body) uploaded on crash.
    final vuln = CrashReporter().report(state);

    // SECURE: allowlist + redact + drop bodies before uploading.
    final secure = CrashReporter().reportSafe(state);

    // The crash pipeline attaches the RAW payload to a report that leaves the
    // device. Emit that exact realistic crash report (stack + breadcrumbs +
    // token/PII) to the system log AND the evidence sink so `adb logcat` /
    // the harness capture what a Crashlytics/Sentry upload would have shipped.
    final crashReport =
        'FATAL EXCEPTION: main\n'
        'java.lang.NullPointerException: PaymentController.finalize()\n'
        '\tat com.dvma.training.PaymentController.finalize(PaymentController.java:212)\n'
        '\tat com.dvma.training.CheckoutScreen.onPay(CheckoutScreen.java:88)\n'
        '--- attached app state ---\n'
        '${vuln.payload}';
    developer.log(crashReport, name: 'DVMA-CRASH');
    await DvmaEvidence.record(
      SensitiveDataInCrashReportsScreen.vulnId,
      'crash-report',
      crashReport,
    );

    if (!mounted) return;
    setState(() {
      _sending = false;
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    final lingo = PlatformLingo.current();
    return VulnDemoScaffold(
      vulnId: SensitiveDataInCrashReportsScreen.vulnId,
      title: 'Sensitive Data in Crash Reports',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'When the app crashes, the diagnostics pipeline snapshots the '
          'current application state and recent breadcrumbs, then ships that '
          'report to a third-party crash service. Developers assume the auth '
          'token, the password, and the last request body only ever lived in '
          'memory - but the crash reporter captures and exfiltrates exactly '
          'that state on failure. The raw crash report (stack trace, '
          'breadcrumbs, token/PII) is emitted to the system log and the '
          'evidence sink, so ${lingo.logReadTool} captures exactly what a real '
          'crash upload would have shipped. The secure path '
          'allowlists non-sensitive fields, redacts tokens/PII, and drops '
          'request/response bodies before uploading.',
      children: [
        DemoActionButton(
          label: _sending ? 'Uploading…' : 'Trigger crash and upload report',
          onPressed: _sending ? () {} : () => _run(),
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'raw crash payload exfiltrated (unscrubbed)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'scrubbed crash payload (allowlisted / redacted)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
