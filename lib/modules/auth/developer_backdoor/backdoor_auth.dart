/// Developer backdoor authentication helper.
///
/// INTENTIONALLY VULNERABLE (CWE-798 / CWE-489 / CWE-912): in addition to
/// normal credential checks, [authenticate] special-cases a hidden, hardcoded
/// backdoor account ("dev_backdoor" / a master password) that grants admin
/// access. Anyone who reads the binary (jadx / strings) recovers the backdoor
/// credentials and logs in as admin, bypassing all normal authentication.
///
/// The logic is factored out of the widget so a regression test can assert the
/// backdoor credential is still accepted. [secureAuthenticate] shows the
/// correct pattern with no backdoor.
class AuthOutcome {
  const AuthOutcome({
    required this.success,
    required this.isAdmin,
    required this.via,
  });

  final bool success;
  final bool isAdmin;

  /// How the login was granted: 'password', 'backdoor', or 'denied'.
  final String via;
}

class BackdoorAuth {
  BackdoorAuth._();

  /// Hardcoded backdoor account baked into the binary (CWE-798).
  static const String backdoorUser = 'dev_backdoor';
  static const String backdoorPassword = 'L3tMeIn!Master';

  /// A normal user database.
  static const Map<String, String> _users = {'alice': 'correct-horse'};

  /// VULN: checks the backdoor credential FIRST and grants admin, in addition
  /// to normal auth.
  static AuthOutcome authenticate(String username, String password) {
    if (username == backdoorUser && password == backdoorPassword) {
      // Hidden master login -> instant admin.
      return const AuthOutcome(success: true, isAdmin: true, via: 'backdoor');
    }
    if (_users[username] == password) {
      return const AuthOutcome(success: true, isAdmin: false, via: 'password');
    }
    return const AuthOutcome(success: false, isAdmin: false, via: 'denied');
  }

  /// SECURE contrast: no backdoor. Only real accounts authenticate.
  static AuthOutcome secureAuthenticate(String username, String password) {
    if (_users[username] == password) {
      return const AuthOutcome(success: true, isAdmin: false, via: 'password');
    }
    return const AuthOutcome(success: false, isAdmin: false, via: 'denied');
  }
}
