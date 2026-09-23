/// Weak password-policy helper.
///
/// INTENTIONALLY VULNERABLE (CWE-521): the "policy" accepts effectively any
/// non-empty password, single characters, no complexity, no length, and
/// common passwords like "123456". A secure policy enforces length + checks
/// against breach/common lists.
///
/// Pure Dart so a unit test can assert a 1-char password is still accepted.
class PasswordPolicy {
  PasswordPolicy._();

  /// The only rule: not empty. Everything else is allowed.
  static bool isAcceptable(String password) => password.isNotEmpty;

  /// A cosmetic "strength" label that has no bearing on acceptance.
  static String strengthLabel(String password) {
    if (password.isEmpty) return 'empty';
    if (password.length < 4) return 'accepted anyway (very weak)';
    return 'accepted';
  }
}
