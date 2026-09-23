import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'insecure_output_handler.dart';

/// Insecure Output Handling (LLM05).
///
/// LLM output is rendered unsanitized into a real WebView (the emitted
/// `<script>` executes) and concatenated into a real SQLite statement (the
/// injected SQL executes against the on-device db).
class InsecureOutputHandlingScreen extends StatefulWidget {
  const InsecureOutputHandlingScreen({super.key});

  static const String vulnId = 'insecure_output_handling';

  @override
  State<InsecureOutputHandlingScreen> createState() =>
      _InsecureOutputHandlingScreenState();
}

class _InsecureOutputHandlingScreenState
    extends State<InsecureOutputHandlingScreen> {
  // Model output that a prompt-injected assistant might emit: an XSS payload
  // that rewrites document.title (readable proof the script ran) and a stacked
  // SQL statement that drops the neighbouring secrets table.
  final _output = TextEditingController(
    text: "<script>document.title='pwned:'+document.cookie</script>",
  );
  final _sqlOutput = TextEditingController(text: "x'); DROP TABLE secrets;--");

  WebViewController? _web;
  String? _webTitle;
  String? _html;
  InsecureSqlResult? _sql;
  bool _running = false;

  @override
  void initState() {
    super.initState();
    if (supportsRealWebView) {
      _web = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted);
    }
  }

  Future<void> _handle() async {
    if (_running) return;
    setState(() => _running = true);
    final html = InsecureOutputHandler.renderToHtml(_output.text);

    // Real XSS sink: load the unsanitized HTML into the live WebView, let the
    // injected <script> run, then read document.title back to prove execution.
    String? title;
    final web = _web;
    if (web != null) {
      await web.loadHtmlString(html);
      await Future<void>.delayed(const Duration(milliseconds: 350));
      final t = await web.runJavaScriptReturningResult('document.title');
      title = t.toString().replaceAll('"', '');
    }

    // Real SQLi sink: run the concatenated statement against the on-device db.
    final statement = InsecureOutputHandler.toSqlQuery(_sqlOutput.text);
    final sql = await InsecureOutputDb.runInjectedSql(statement);
    final dbPath = await InsecureOutputDb.dbPath();

    if (!mounted) return;
    setState(() {
      _html = html;
      _webTitle = title;
      _sql = sql;
      _running = false;
    });

    DvmaEvidence.record(
      InsecureOutputHandlingScreen.vulnId,
      'unsafe-output',
      'htmlSink: $html\n'
          'webViewTitleAfterScript: ${title ?? "(WebView unavailable on host)"}\n'
          'sqlSink: $statement\n'
          'secretsTableSurvived: ${sql?.secretsTableSurvived}\n'
          'notesRows: ${sql?.noteBodies.length}\n'
          'dbPath: ${dbPath ?? "(db factory unavailable)"}',
    );
  }

  @override
  Widget build(BuildContext context) {
    final sql = _sql;
    return VulnDemoScaffold(
      vulnId: InsecureOutputHandlingScreen.vulnId,
      title: 'Insecure Output Handling',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The app treats LLM output as trusted and pipes it, unsanitized, into '
          'a real WebView (HTML) and a real SQLite statement. A prompt-injected '
          'model emits <script> or SQL syntax and it executes: XSS runs in the '
          'WebView (proven by the rewritten page title) and injected SQL runs '
          'against the on-device db (the secrets table is dropped). Output must '
          'be escaped/parameterized for its sink.',
      children: [
        TextField(
          controller: _output,
          maxLines: 2,
          decoration: const InputDecoration(labelText: 'LLM output -> WebView'),
        ),
        TextField(
          controller: _sqlOutput,
          maxLines: 2,
          decoration: const InputDecoration(labelText: 'LLM output -> SQL'),
        ),
        DemoActionButton(
          label: _running ? 'Handling...' : 'Handle output',
          onPressed: _running ? () {} : _handle,
        ),
        if (_html != null)
          EvidencePanel(
            label: 'HTML loaded into WebView (unescaped)',
            value: _html!,
          ),
        if (_webTitle != null)
          EvidencePanel(
            label: 'document.title after injected script ran (XSS)',
            value: _webTitle!,
          ),
        if (sql != null) ...[
          EvidencePanel(
            label: 'SQL executed (unparameterized)',
            value: sql.statement,
          ),
          EvidencePanel(
            label: 'secrets table survived?',
            value: sql.secretsTableSurvived
                ? 'yes'
                : 'NO - injected DROP TABLE executed',
          ),
          if (sql.execError != null)
            EvidencePanel(label: 'sql engine response', value: sql.execError!),
        ],
        if (_web != null) RealWebViewView(controller: _web),
      ],
    );
  }
}
