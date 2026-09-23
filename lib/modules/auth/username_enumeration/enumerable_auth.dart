/// Username enumeration login helper.
///
/// INTENTIONALLY VULNERABLE (CWE-204 / CWE-203): the login flow returns
/// DISTINGUISHABLE responses depending on whether the username exists. A wrong
/// password for a real account returns "invalid password", while an unknown
/// account returns "no such user". An attacker can therefore enumerate valid
/// accounts simply by observing which error comes back - without ever knowing a
/// password.
///
/// The logic is factored out of the widget so a regression test can assert the
/// two responses are still distinguishable. [secureAuthenticate] shows the
/// correct pattern: a single generic error for any failure.
class LoginResult {
  const LoginResult({required this.success, required this.message});

  final bool success;
  final String message;
}

class EnumerableAuth {
  EnumerableAuth._();

  /// A tiny stand-in user database (username -> password).
  static const Map<String, String> _users = {
    'alice': 'correct-horse',
    'bob': 'battery-staple',
  };

  /// VULN: leaks account existence through differing error messages.
  static LoginResult authenticate(String username, String password) {
    if (!_users.containsKey(username)) {
      // Distinct response for an unknown account.
      return const LoginResult(success: false, message: 'No such user');
    }
    if (_users[username] != password) {
      // Distinct response for a valid account with a wrong password.
      return const LoginResult(success: false, message: 'Invalid password');
    }
    return const LoginResult(success: true, message: 'Welcome');
  }

  /// SECURE contrast: one generic error regardless of which part failed, so an
  /// attacker cannot tell a real account from an unknown one.
  static LoginResult secureAuthenticate(String username, String password) {
    final ok = _users[username] == password;
    return LoginResult(
      success: ok,
      message: ok ? 'Welcome' : 'Invalid username or password',
    );
  }
}
