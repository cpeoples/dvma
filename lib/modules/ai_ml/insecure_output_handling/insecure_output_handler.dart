/// Insecure output-handling helper.
///
/// INTENTIONALLY VULNERABLE (CWE-79 / CWE-89): the app takes the LLM's output
/// and uses it in a security-sensitive sink WITHOUT sanitization - injecting it
/// straight into a WebView's HTML and concatenating it into a SQL statement. If
/// the model is coaxed into emitting `<script>` or SQL syntax, it executes: the
/// script runs in the WebView (real XSS) and the injected SQL runs against a
/// real on-device SQLite db (real SQLi).
library;

import 'dart:io';

import 'package:sqflite/sqflite.dart';

/// Builds the sink payloads and drives the two real sinks.
class InsecureOutputHandler {
  InsecureOutputHandler._();

  /// Renders model output directly into a WebView page - no HTML-escaping, so
  /// an emitted `<script>` executes. Nothing else runs in the page, so the only
  /// way `document.title` changes is if the injected model output itself ran
  /// script - which is what the screen reads back to prove the XSS fired.
  static String renderToHtml(String modelOutput) =>
      '<html><body><div id="answer">$modelOutput</div></body></html>';

  /// Builds a SQL statement by concatenating model output - no parameterization,
  /// so `'); DROP TABLE ...--` or a stacked statement executes verbatim.
  static String toSqlQuery(String modelOutput) =>
      "INSERT INTO notes(body) VALUES ('$modelOutput')";
}

/// Real on-device SQLite sink for the injected LLM output.
///
/// INTENTIONALLY VULNERABLE: [runInjectedSql] hands the attacker-built statement
/// to `execute()` with no parameterization, so injected SQL (stacked statements,
/// `--` comments, subqueries) runs against the real db. The screen reads the
/// resulting row count / table state back to prove the injection landed.
/// Best-effort: under `flutter test` (no `databaseFactory`) it no-ops to null.
class InsecureOutputDb {
  InsecureOutputDb._();

  static const String dbFileName = 'dvma_llm_output.db';

  static Future<Database?> _open() async {
    try {
      final dir = await getDatabasesPath();
      final path = '$dir/$dbFileName';
      return await openDatabase(
        path,
        version: 1,
        onCreate: (db, _) async {
          await db.execute(
            'CREATE TABLE notes(id INTEGER PRIMARY KEY, '
            'body TEXT NOT NULL)',
          );
          // A neighbouring "sensitive" table an injected statement can read/drop.
          await db.execute('CREATE TABLE secrets(name TEXT, value TEXT)');
          await db.insert('secrets', {
            'name': 'api_key',
            'value': 'DVMA{sqli}',
          });
        },
      );
    } catch (_) {
      return null;
    }
  }

  /// Absolute db path (adb-pullable), or null when unavailable.
  static Future<String?> dbPath() async {
    try {
      final dir = await getDatabasesPath();
      final path = '$dir/$dbFileName';
      if (!await File(path).exists()) {
        final db = await _open();
        await db?.close();
      }
      return path;
    } catch (_) {
      return null;
    }
  }

  /// VULN: run the attacker-built statement unparameterized. Returns the notes
  /// table state after execution (rows + whether `secrets` survived) so the
  /// caller can prove an injected `DROP`/subquery actually executed. Null when
  /// the platform db factory is unavailable.
  static Future<InsecureSqlResult?> runInjectedSql(String statement) async {
    Database? db;
    try {
      db = await _open();
      if (db == null) return null;
      String? execError;
      try {
        // No parameters: stacked statements / comments / subqueries all fire.
        await db.execute(statement);
      } catch (e) {
        // A malformed injection can throw; that itself is evidence the raw
        // string reached the SQL engine.
        execError = e.toString();
      }
      final notes = await db.query('notes');
      final secretsSurvived = (await db.rawQuery(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='secrets'",
      )).isNotEmpty;
      return InsecureSqlResult(
        statement: statement,
        noteBodies: [for (final r in notes) r['body'] as String? ?? ''],
        secretsTableSurvived: secretsSurvived,
        execError: execError,
      );
    } catch (_) {
      return null;
    } finally {
      await db?.close();
    }
  }
}

/// Post-execution state of the real db after an injected statement ran.
class InsecureSqlResult {
  const InsecureSqlResult({
    required this.statement,
    required this.noteBodies,
    required this.secretsTableSurvived,
    this.execError,
  });

  final String statement;
  final List<String> noteBodies;

  /// False if an injected `DROP TABLE secrets` actually removed the table.
  final bool secretsTableSurvived;
  final String? execError;
}
