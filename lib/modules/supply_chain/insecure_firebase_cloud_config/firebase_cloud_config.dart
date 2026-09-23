/// Insecure Firebase / cloud backend config helper.
///
/// INTENTIONALLY VULNERABLE (CWE-1188 / CWE-668 / CWE-798): the Firebase
/// Realtime Database URL and a cloud API key/secret are hardcoded in the app
/// (recoverable with strings/jadx), and the backend's security rules are
/// world-readable. [fetchAllRecords] performs an UNAUTHENTICATED read that
/// returns every user's records - not just the current user's - because the
/// rules grant public read access.
///
/// This is offline + deterministic (the "cloud" is a local map) so a test can
/// assert an unauthenticated read still returns other users' data. In the real
/// world the check is hitting the exposed endpoint, e.g.
/// `curl https://<db>.firebaseio.com/users.json`.
///
/// The vulnerable [fetchAllRecords] ignores auth; [secureFetchOwnRecords]
/// requires a valid token and scopes the read to the caller.
class FirebaseCloudConfig {
  FirebaseCloudConfig._();

  // --- Hardcoded (fake) cloud config baked into the binary --------------------
  static const String databaseUrl =
      'https://dvma-training-default-rtdb.firebaseio.com';
  static const String apiKey = 'AIzaSyD-DVMA-FAKE-KEY-0123456789abcdefGHI';
  static const String cloudSecret = 'firebase-admin-secret-do-not-ship';

  /// The backend's (world-readable) security rules.
  static const Map<String, Object> securityRules = {
    'rules': {
      '.read': true, // VULN: anyone can read
      '.write': true, // VULN: anyone can write
    },
  };

  /// The "cloud" database contents (offline stand-in). Keyed by user id.
  static const Map<String, Map<String, String>> _database = {
    'alice': {'email': 'alice@example.com', 'card': '4111 1111 1111 1111'},
    'bob': {'email': 'bob@example.com', 'ssn': '555-11-0000'},
    'carol': {'email': 'carol@example.com', 'card': '5500 0000 0000 0004'},
  };

  /// VULN: an unauthenticated read. Because `.read` is public, this returns
  /// every user's record regardless of who is asking (or whether they are
  /// logged in at all).
  static Map<String, Map<String, String>> fetchAllRecords() {
    // No token check whatsoever.
    return Map<String, Map<String, String>>.from(_database);
  }

  /// SECURE contrast: require a valid session token and return only the
  /// caller's own record.
  static Map<String, String>? secureFetchOwnRecords({
    required String userId,
    required String? token,
  }) {
    if (token == null || token.isEmpty) return null; // must be authenticated
    return _database[userId];
  }
}
