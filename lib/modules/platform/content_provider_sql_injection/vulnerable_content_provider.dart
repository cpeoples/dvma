/// Content-provider SQL-injection helper.
///
/// INTENTIONALLY VULNERABLE (CWE-89): an exported content provider builds its
/// query by string concatenation of untrusted selection input instead of using
/// parameterized `selectionArgs`. A tiny in-memory SQL engine simulates the
/// resulting query so the injection is demonstrable and testable offline
/// (sqflite needs a device).
class VulnerableContentProvider {
  VulnerableContentProvider();

  // A stand-in `users` table. The `secret` column should never be exposed.
  final List<Map<String, Object?>> _users = const [
    {'id': 1, 'name': 'alice', 'secret': 'DVMA{alice_secret}'},
    {'id': 2, 'name': 'bob', 'secret': 'DVMA{bob_secret}'},
    {'id': 3, 'name': 'admin', 'secret': 'DVMA{admin_secret}'},
  ];

  /// Builds the raw SQL by concatenating the caller-supplied selection.
  /// A safe provider would use `WHERE name = ?` + selectionArgs.
  static String buildQuery(String selection) =>
      "SELECT id, name FROM users WHERE name = '$selection'";

  /// "Executes" the concatenated query. Recognizes a classic
  /// `' OR '1'='1` tautology and the `UNION SELECT secret` exfiltration that
  /// string-concatenation enables, returning rows the caller shouldn't see.
  List<Map<String, Object?>> query(String selection) {
    final sql = buildQuery(selection).toLowerCase();

    // Tautology / boolean injection: dump everything.
    if (sql.contains("or '1'='1") || sql.contains('or 1=1')) {
      return List.of(_users);
    }
    // UNION-based secret exfiltration.
    if (sql.contains('union') && sql.contains('secret')) {
      return _users.map((u) => {'id': u['id'], 'name': u['secret']}).toList();
    }
    // Otherwise behave like a normal equality match.
    final match = RegExp(r"name = '([^']*)'").firstMatch(buildQuery(selection));
    final name = match?.group(1) ?? '';
    return _users
        .where((u) => u['name'] == name)
        .map((u) => {'id': u['id'], 'name': u['name']})
        .toList();
  }
}
