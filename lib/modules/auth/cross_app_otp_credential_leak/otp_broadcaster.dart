/// Cross-App OTP / Credential Leak helper.
///
/// INTENTIONALLY VULNERABLE (CWE-926 / CWE-200): a simulated authenticator app
/// publishes the current time-based OTP plus an auth deep link
/// (`myauth://login?otp=...&token=...`) to an UNPROTECTED shared surface
/// (exported broadcast / shared clipboard). Any co-resident app can read that
/// surface with no special permission and recover the second factor - the
/// Authenticator CVE-2026-26123 class.
///
/// This is an offline + deterministic simulation of the real mechanism: the
/// "OTP" is derived from a fixed seed plus a caller-supplied counter (so tests
/// are stable), and the "broadcast bus" is an in-memory field instead of an
/// Android Intent/Binder. A test can assert that [readAsMaliciousApp] recovers
/// the OTP after an unprotected [broadcastOtp], but recovers nothing after the
/// permission-scoped [broadcastOtpSecure].
class OtpBroadcaster {
  OtpBroadcaster({this.seed = 0xD7A9});

  /// Fixed secret seed baked into the authenticator (stand-in for the shared
  /// TOTP secret). Combined with a counter to produce a deterministic OTP.
  final int seed;

  /// The unprotected shared surface a malicious co-resident app can read.
  /// Anyone (no permission) may read whatever was last broadcast here.
  String? _unprotectedBus;

  /// The permission-scoped surface: only an allowlisted package receives it.
  final Map<String, String> _scopedInbox = {};

  /// Packages allowed to receive the OTP on the secure channel.
  static const Set<String> _allowlistedPackages = {'com.dvma.authenticator'};

  /// Deterministic time-based OTP: derived from [seed] + [counter] so a test
  /// gets a stable 6-digit code. Models a TOTP where `counter` is the time step.
  String currentOtp(int counter) {
    final mixed =
        (seed * 1103515245 + counter * 12345 + 0x9E3779B9) & 0x7FFFFFFF;
    return (mixed % 1000000).toString().padLeft(6, '0');
  }

  /// The auth deep link a legitimate handler would consume - but which leaks
  /// the OTP and a bearer token in the clear when broadcast unprotected.
  String authDeepLink(int counter) {
    final otp = currentOtp(counter);
    final token = (seed ^ (counter * 2654435761)).toRadixString(16);
    return 'myauth://login?otp=$otp&token=$token';
  }

  /// VULN: publishes the current OTP + auth deep link to an UNPROTECTED shared
  /// surface. No permission or package check, so any app can read it back.
  void broadcastOtp(int counter) {
    _unprotectedBus = authDeepLink(counter);
  }

  /// SECURE contrast: deliver only to an allowlisted, permission-holding
  /// package. A caller not on the allowlist gets nothing on the shared bus.
  void broadcastOtpSecure(int counter, String callerPackage) {
    if (!_allowlistedPackages.contains(callerPackage)) {
      return; // reject: not an allowlisted recipient
    }
    _scopedInbox[callerPackage] = authDeepLink(counter);
  }

  /// Simulates a malicious co-resident app (no special permission) reading the
  /// shared surface. It only ever sees the UNPROTECTED bus.
  String? readAsMaliciousApp() => _unprotectedBus;

  /// Extracts just the OTP from whatever the malicious app captured, or null.
  String? capturedOtp() {
    final link = readAsMaliciousApp();
    if (link == null) return null;
    return Uri.parse(link).queryParameters['otp'];
  }
}
