import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/provider_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'vulnerable_content_provider.dart';

/// Content Provider SQL Injection.
///
/// Exported content provider builds SQL by string concatenation.
class ContentProviderSqlInjectionScreen extends StatefulWidget {
  const ContentProviderSqlInjectionScreen({super.key});

  static const String vulnId = 'content_provider_sql_injection';

  @override
  State<ContentProviderSqlInjectionScreen> createState() =>
      _ContentProviderSqlInjectionScreenState();
}

class _ContentProviderSqlInjectionScreenState
    extends State<ContentProviderSqlInjectionScreen> {
  final _provider = VulnerableContentProvider();
  final _selection = TextEditingController(text: "x' UNION SELECT secret --");
  String? _sql;
  String? _rows;
  String? _nativeLeaked;

  Future<void> _run() async {
    // Offline model: build + run the concatenated query (kept for tests / iOS).
    final rows = _provider.query(_selection.text);
    // On Android, run the SAME injection against the real exported
    // VulnerableProvider through the app's ContentResolver, then read back the
    // rows the provider actually leaked from its seeded SQLite db.
    final native = await ProviderIpcBridge.sqlInject(_selection.text);
    if (native != null && native.isNotEmpty) {
      await DvmaEvidence.record(
        ContentProviderSqlInjectionScreen.vulnId,
        'sql-injection',
        'exported provider leaked rows for concatenated selection '
            '"${_selection.text}":\n$native',
      );
    }
    if (!mounted) return;
    setState(() {
      _sql = VulnerableContentProvider.buildQuery(_selection.text);
      _rows = rows.map((r) => r.toString()).join('\n');
      _nativeLeaked = native;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ContentProviderSqlInjectionScreen.vulnId,
      title: 'Content Provider SQL Injection',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'An exported content provider concatenates the caller-supplied '
          'selection straight into SQL instead of using parameterized args. A '
          'malicious app (drozer / `adb shell content query`) supplies a '
          'UNION/tautology selection and exfiltrates the secret column. On a '
          'device the REAL exported provider '
          '(content://com.dvma.provider.vuln/users) runs the concatenated query '
          'over a seeded SQLite db and returns the leaked rows below; offline '
          'an in-memory engine mirrors it so the demo stays testable.',
      children: [
        TextField(
          controller: _selection,
          decoration: const InputDecoration(labelText: 'selection (attacker)'),
        ),
        DemoActionButton(label: 'Query provider', onPressed: _run),
        if (_sql != null)
          EvidencePanel(label: 'concatenated SQL', value: _sql!),
        if (_rows != null)
          EvidencePanel(label: 'rows returned (leaked)', value: _rows!),
        if (_nativeLeaked != null)
          EvidencePanel(
            label: 'exported provider leaked rows (real SQLite via resolver)',
            value: _nativeLeaked!,
          ),
      ],
    );
  }
}
