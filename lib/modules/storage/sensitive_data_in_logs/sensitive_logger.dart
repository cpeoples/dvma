import 'dart:developer' as developer;

/// Sensitive-data logging helper.
///
/// INTENTIONALLY VULNERABLE (CWE-532): builds and emits log lines containing
/// PII, tokens, and passwords in cleartext, exactly as they would appear in
/// `adb logcat` / Console.app. The formatting is factored out so a unit test
/// can assert the secrets are still present (unredacted) in the log output.
class SensitiveLogger {
  SensitiveLogger();

  final List<String> emitted = [];

  /// Formats a login event with no redaction. A secure logger would mask or
  /// omit the password and token entirely.
  static String formatLogin({
    required String username,
    required String password,
    required String token,
  }) => 'AUTH login user=$username password=$password token=$token';

  /// "Logs" the event: appends to [emitted] and prints to the system log.
  String logLogin({
    required String username,
    required String password,
    required String token,
  }) {
    final line = formatLogin(
      username: username,
      password: password,
      token: token,
    );
    emitted.add(line);
    // Goes straight to the device log; readable by any app with READ_LOGS or
    // via a USB cable.
    developer.log(line, name: 'DVMA');
    return line;
  }
}
