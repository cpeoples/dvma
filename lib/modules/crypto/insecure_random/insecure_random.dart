import 'dart:math';

/// Insecure randomness helper.
///
/// INTENTIONALLY VULNERABLE (CWE-330 / CWE-338): session tokens are generated
/// with the non-cryptographic [Random] seeded with a *known* seed, so the
/// entire token stream is predictable. A secure app would use [Random.secure].
///
/// Because the seed is fixed, [predictableToken] is deterministic, which both
/// demonstrates the flaw and lets a unit test assert the exact predicted
/// sequence.
class InsecureRandom {
  InsecureRandom._();

  /// A fixed seed makes the output fully predictable (the whole point).
  static const int knownSeed = 1337;

  static const String _alphabet =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

  /// Generates [count] tokens from a fixed-seed non-secure PRNG. An attacker
  /// who knows (or brute-forces) the seed can reproduce every token.
  static List<String> predictableTokens({int count = 3, int length = 16}) {
    final rng = Random(knownSeed);
    return List.generate(
      count,
      (_) => List.generate(
        length,
        (_) => _alphabet[rng.nextInt(_alphabet.length)],
      ).join(),
    );
  }

  /// Single predictable token (first of the sequence).
  static String predictableToken({int length = 16}) =>
      predictableTokens(count: 1, length: length).first;
}
