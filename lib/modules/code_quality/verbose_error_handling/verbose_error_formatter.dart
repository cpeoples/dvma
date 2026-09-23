/// Verbose error-handling helper.
///
/// INTENTIONALLY VULNERABLE (CWE-209 / CWE-497): renders full exception details
///, message, stack trace, and internal context (DB DSN, file paths, config) -
/// straight to the UI. This hands an attacker a map of the internals. A safe
/// handler shows a generic message and logs details server-side.
///
/// The formatter is pure Dart so a unit test can assert the sensitive internals
/// are still present in the surfaced error text.
class VerboseErrorFormatter {
  VerboseErrorFormatter._();

  /// Internal context that should never reach the user.
  static const Map<String, String> internalContext = {
    'db_dsn': 'postgres://dvma:hunter2@10.0.0.5:5432/prod',
    'config_path': '/data/data/com.dvma/files/config.yaml',
    'api_key': 'DVMA{verbose_error_key}',
  };

  /// Builds the over-verbose error string surfaced to the user.
  static String format(Object error, StackTrace stack) {
    final ctx = internalContext.entries
        .map((e) => '  ${e.key}=${e.value}')
        .join('\n');
    return 'ERROR: $error\n\nSTACK TRACE:\n$stack\n\nCONTEXT:\n$ctx';
  }

  /// Triggers a representative failure and returns the verbose surface text.
  static String triggerAndFormat() {
    try {
      // A typical internal failure (e.g. bad parse) with a real stack trace.
      throw const FormatException('Invalid transaction record at row 42');
    } catch (e, st) {
      return format(e, st);
    }
  }
}
