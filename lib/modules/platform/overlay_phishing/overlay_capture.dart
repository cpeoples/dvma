/// Pure-Dart simulation of an overlay / tapjacking-style phishing capture.
///
/// INTENTIONALLY VULNERABLE (CWE-1021 / CWE-290): a credential field has no
/// obscured-touch / overlay protection, so a malicious overlay drawn on top of
/// it (a look-alike view granted the SYSTEM_ALERT_WINDOW / "draw over other
/// apps" permission) captures everything the user types. This models tapjacking
/// where the victim believes they are typing into the real app.
///
/// This is a faithful Dart SIMULATION; the real exploit is platform-level (an
/// overlay window + the app failing to set `filterTouchesWhenObscured` /
/// FLAG_SECURE). The vulnerable [CredentialField] forwards input to any
/// attached overlay; the secure one drops input while obscured.
class MaliciousOverlay {
  final List<String> _captured = [];

  /// The credentials the overlay has phished so far.
  List<String> get captured => List.unmodifiable(_captured);

  void capture(String input) => _captured.add(input);
}

class CredentialField {
  /// VULN: no obscured-touch protection. When an [overlay] is attached, typed
  /// input is delivered to it (captured) as well as to the app.
  MaliciousOverlay? overlay;

  final List<String> appReceived = [];

  /// Simulates the user typing [input] while the field may be obscured.
  void type(String input) {
    // VULN: the field processes input even when covered, and the overlay on
    // top of it also receives the same touch/keystrokes.
    appReceived.add(input);
    overlay?.capture(input);
  }
}

class SecureCredentialField {
  MaliciousOverlay? overlay;
  final List<String> appReceived = [];

  /// SECURE contrast: with obscured-touch filtering (filterTouchesWhenObscured
  /// / FLAG_SECURE), input is dropped while another window is on top, so the
  /// overlay captures nothing and the field ignores the obscured touches.
  void type(String input, {bool obscured = true}) {
    if (obscured) {
      // Touch is filtered out entirely; nothing reaches the overlay or the app.
      return;
    }
    appReceived.add(input);
  }
}
