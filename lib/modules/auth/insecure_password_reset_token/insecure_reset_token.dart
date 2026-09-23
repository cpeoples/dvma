import 'dart:math';

/// Insecure password-reset token / magic-link helper.
///
/// INTENTIONALLY VULNERABLE (CWE-640 / CWE-330): reset tokens are short,
/// generated from a non-cryptographic, seedable `Random()`, and never expire.
/// Because the generator is seeded (here, off a monotonically increasing
/// counter) two tokens issued close together are related and predictable: an
/// attacker who sees or guesses one issued token can derive others and take
/// over accounts.
///
/// The logic is factored out of the widget so a regression test can assert the
/// tokens are predictable and non-expiring. [secureToken] shows the correct
/// pattern: a long `Random.secure()` token with a TTL.
class ResetToken {
  ResetToken({
    required this.value,
    required this.issuedAt,
    required this.expiresAt,
  });

  final String value;
  final DateTime issuedAt;

  /// Null means the token never expires (the vulnerable case).
  final DateTime? expiresAt;

  bool isValidAt(DateTime now) => expiresAt == null || now.isBefore(expiresAt!);
}

class InsecureResetToken {
  InsecureResetToken._();

  /// A predictable, ever-incrementing seed source. not random.
  static int _counter = 1000;

  /// VULN: derives a short token from a seeded, non-secure PRNG and sets no
  /// expiry. Tokens issued in sequence are trivially related/guessable.
  static ResetToken issue({DateTime? now}) {
    final seed = _counter++;
    final rng = Random(seed); // predictable: seed is guessable/sequential
    final n = rng.nextInt(1000000); // short 6-digit space
    final issued = now ?? DateTime.now();
    return ResetToken(
      value: n.toString().padLeft(6, '0'),
      issuedAt: issued,
      expiresAt: null, // never expires
    );
  }

  /// SECURE contrast: a long cryptographically-random token with a TTL.
  static ResetToken secureToken({
    DateTime? now,
    Duration ttl = const Duration(minutes: 15),
  }) {
    final rng = Random.secure();
    final bytes = List<int>.generate(32, (_) => rng.nextInt(256));
    final value = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    final issued = now ?? DateTime.now();
    return ResetToken(
      value: value,
      issuedAt: issued,
      expiresAt: issued.add(ttl),
    );
  }

  /// Test/demo helper to reset the sequential counter.
  static void resetCounter() => _counter = 1000;
}
