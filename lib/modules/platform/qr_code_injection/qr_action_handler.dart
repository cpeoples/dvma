/// QR-injection handler.
///
/// INTENTIONALLY VULNERABLE (CWE-20): the scanner trusts scanned content and
/// acts on it with no validation, following deep links, opening `javascript:`
/// / `file:` URIs, and auto-executing app "commands" embedded in the QR. A safe
/// handler would allow-list schemes/hosts and require user confirmation.
///
/// Pure Dart so a unit test can assert a hostile payload is still auto-executed.
class QrActionHandler {
  QrActionHandler._();

  /// Classifies + "executes" scanned content. Returns the action taken.
  static String handle(String scanned) {
    final value = scanned.trim();

    // App command scheme: executed with no confirmation.
    if (value.startsWith('dvma://')) {
      return 'AUTO-EXECUTED app command: $value';
    }
    // Dangerous URI schemes followed blindly.
    if (value.startsWith('javascript:')) {
      return 'INJECTED into WebView: $value';
    }
    if (value.startsWith('file:')) {
      return 'OPENED local file: $value';
    }
    if (value.startsWith('http://') || value.startsWith('https://')) {
      return 'NAVIGATED to: $value';
    }
    // Anything else is still trusted as free text / payload.
    return 'PROCESSED untrusted payload verbatim: $value';
  }

  /// A hostile sample payload (an app-command that transfers funds).
  static const String hostileSample =
      'dvma://transfer?to=attacker&amount=10000';
}
