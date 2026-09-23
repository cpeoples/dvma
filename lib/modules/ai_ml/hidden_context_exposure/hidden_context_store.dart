/// A deliberately-insecure context store for an in-app assistant.
///
/// INTENTIONALLY VULNERABLE (CWE-200 / CWE-668, OWASP LLM07 successor "hidden
/// context exposure"): records for *different* owners and different trust
/// levels are dumped into one flat list with no partitioning. When the app
/// assembles the prompt it concatenates everything it can reach, so another
/// user's private record and an internal secret end up in the current user's
/// context window - and the model happily surfaces them.
///
/// Deterministic + offline so a test can assert the private record leaks into
/// the assembled context.
class HiddenContextStore {
  final List<ContextRecord> _records = [];

  List<ContextRecord> get records => List.unmodifiable(_records);

  void add(ContextRecord record) => _records.add(record);

  /// Assembles the context block for [currentUser].
  ///
  /// VULN: there is no owner check and no trust partition. Every record is
  /// included regardless of who owns it or whether it is a secret, so private
  /// data belonging to other users (and internal secrets) leaks in.
  String assembleContext(String currentUser) {
    return _records
        .map((r) => '[${r.owner}/${r.visibility}] ${r.content}')
        .join('\n');
  }

  /// What a correctly-partitioned store would return: only the current user's
  /// own non-secret records.
  String secureAssembleContext(String currentUser) {
    return _records
        .where((r) => r.owner == currentUser && r.visibility != 'secret')
        .map((r) => '[${r.owner}/${r.visibility}] ${r.content}')
        .join('\n');
  }
}

/// A single stored context record with an owner and a visibility level.
class ContextRecord {
  ContextRecord({
    required this.owner,
    required this.visibility,
    required this.content,
  });

  /// Who the record belongs to (or 'system' for internal data).
  final String owner;

  /// One of: 'private', 'secret', 'public'.
  final String visibility;

  final String content;
}
