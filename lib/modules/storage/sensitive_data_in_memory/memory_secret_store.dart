/// Sensitive data in memory helper.
///
/// INTENTIONALLY VULNERABLE (CWE-316 / CWE-226): secrets (a password and a
/// symmetric key) are copied into a long-lived, process-global store and are
/// never cleared after use. Because the objects stay reachable for the lifetime
/// of the process, a memory dump (fridump / objection / gdb-lldb) can scan the
/// retained heap and recover the plaintext secret long after the login flow
/// that "used" it has finished.
///
/// The logic is factored out of the widget so a regression test can assert the
/// [dumpMemory] scan still recovers the secret (an accidental "fix" that
/// zeroized the store would break the training scenario and fail CI).
///
/// [SecureSecretScope] shows the correct pattern for contrast: it holds the
/// secret only for the duration of a use and wipes it immediately afterward, so
/// a later dump finds nothing.
library;

/// A long-lived, never-cleared store of sensitive material.
class InMemorySecretStore {
  /// VULN: a process-global singleton. Anything written here is retained for
  /// the lifetime of the process and is visible to a heap dump.
  static final InMemorySecretStore instance = InMemorySecretStore._();

  InMemorySecretStore._();

  /// Retained secrets, keyed by a label. Never cleared.
  final Map<String, String> _retained = {};

  /// "Uses" a secret (e.g. to log in / derive a key) and - the bug - keeps a
  /// copy alive in the global store forever.
  void useSecret(String label, String secret) {
    // VULN: no clearing, no zeroization. The reference is retained.
    _retained[label] = secret;
  }

  /// Simulates a process memory dump: a scanner walking retained objects on the
  /// heap recovers every secret still reachable from this store.
  Map<String, String> dumpMemory() => Map<String, String>.from(_retained);

  /// Test/demo helper to reset global state between runs.
  void reset() => _retained.clear();
}

/// The SECURE contrast: a scoped secret that is wiped immediately after use, so
/// it is not retained on the heap for a later dump to find.
class SecureSecretScope {
  final List<int> _bytes;
  bool _cleared = false;

  SecureSecretScope(String secret) : _bytes = secret.codeUnits.toList();

  /// Uses the secret then zeroizes the backing buffer.
  T useThenWipe<T>(T Function(String secret) body) {
    final value = String.fromCharCodes(_bytes);
    try {
      return body(value);
    } finally {
      for (var i = 0; i < _bytes.length; i++) {
        _bytes[i] = 0;
      }
      _cleared = true;
    }
  }

  /// What a memory scan would recover after [useThenWipe]: nothing meaningful.
  String dumpAfterUse() => _cleared ? '' : String.fromCharCodes(_bytes);
}
