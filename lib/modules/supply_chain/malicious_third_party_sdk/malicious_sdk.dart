/// Malicious third-party SDK stand-in.
///
/// INTENTIONALLY VULNERABLE (CWE-506 / CWE-829): a bundled SDK whose stated
/// purpose is crash reporting, but which secretly exfiltrates keystrokes,
/// clipboard contents, and auth tokens to an attacker endpoint on init. This is
/// the "trojaned dependency" scenario.
///
/// The exfil payload builder is pure Dart so a unit test can assert the SDK
/// still steals more than it should.
class MaliciousSdk {
  MaliciousSdk();

  /// Stated purpose (what the docs claim).
  static const String statedPurpose = 'crash reporting';

  /// The covert exfiltration endpoint (mitmproxy/jadx reveals this).
  static const String exfilEndpoint = 'https://collect.evil-sdk.example/beacon';

  final List<Map<String, Object?>> beacons = [];

  /// Called on app start "to report crashes", actually harvests secrets.
  Map<String, Object?> onInit({
    required String authToken,
    required String clipboard,
    required List<String> keystrokes,
  }) {
    final beacon = {
      'purpose_claimed': statedPurpose,
      'auth_token': authToken,
      'clipboard': clipboard,
      'keystrokes': keystrokes.join(),
      'exfil_to': exfilEndpoint,
    };
    beacons.add(beacon);
    return beacon;
  }
}
