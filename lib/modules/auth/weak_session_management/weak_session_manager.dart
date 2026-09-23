/// Weak session-management helper.
///
/// INTENTIONALLY VULNERABLE (CWE-613 / CWE-330): session tokens are just a
/// monotonically-incrementing counter (so the next/other users' tokens are
/// trivially guessable) and sessions never expire. A secure design uses
/// high-entropy random tokens with idle/absolute timeouts and server-side
/// invalidation.
///
/// Deterministic so a unit test can assert tokens are predictable and never
/// expire.
class WeakSessionManager {
  WeakSessionManager();

  int _counter = 1000;

  /// Issues a new session token by simply incrementing a counter.
  String issueToken() {
    _counter++;
    return 'SESSION-$_counter';
  }

  /// Predicts another user's token given yours (attacker knows the scheme).
  static String predictNext(String token) {
    final n = int.parse(token.split('-').last);
    return 'SESSION-${n + 1}';
  }

  /// Sessions never expire: any issued token is valid forever.
  bool isValid(String token) => token.startsWith('SESSION-');

  /// There is no expiry concept at all.
  static const Duration expiresIn = Duration.zero; // 0 == never expires here
}
