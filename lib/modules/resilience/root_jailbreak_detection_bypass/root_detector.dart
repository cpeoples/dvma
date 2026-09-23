/// Root/jailbreak detection, bypassable by design.
///
/// INTENTIONALLY VULNERABLE (CWE-693): the detection result is gated on a
/// single mutable boolean that an attacker hooks/patches to `false` (frida/
/// objection). Even the "real" check just looks for a couple of well-known
/// paths that are trivial to hide.
///
/// Pure Dart so a unit test can assert that flipping [bypassed] defeats it.
class RootDetector {
  RootDetector();

  /// Attacker-controlled: frida sets this true to force "not rooted".
  bool bypassed = false;

  /// Well-known indicators the naive check greps for.
  static const List<String> indicators = [
    '/system/bin/su',
    '/system/app/Superuser.apk',
    'Cydia.app',
  ];

  /// Returns true if the device appears rooted/jailbroken. When [bypassed] is
  /// set, it always returns false regardless of the indicators.
  bool isCompromised({bool indicatorsPresent = true}) {
    if (bypassed) return false; // the whole vulnerability, in one line
    return indicatorsPresent;
  }
}
