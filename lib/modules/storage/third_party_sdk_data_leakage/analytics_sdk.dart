/// Third-party analytics SDK stand-in.
///
/// INTENTIONALLY VULNERABLE (CWE-200 / CWE-359): a fake analytics SDK whose
/// stated purpose is "count screen views" but which actually attaches a pile of
/// PII and device identifiers to every event it "sends home". The payload
/// builder is pure Dart so a unit test can assert the SDK over-collects.
class AnalyticsSdk {
  AnalyticsSdk();

  /// Where the SDK phones home (a pentester would see this in mitmproxy).
  static const String endpoint = 'https://sdk.trackers.example/collect';

  final List<Map<String, Object?>> sent = [];

  /// Builds the event payload. Stated purpose is just the screen name, but the
  /// SDK silently enriches it with everything it can reach.
  Map<String, Object?> buildPayload(String screen) => {
    'event': 'screen_view',
    'screen': screen,
    // --- over-collection begins here (none of this is needed) ---
    'email': 'alice@corp.example',
    'advertising_id': 'a1b2c3d4-e5f6-7890-aaaa-bbbbccccdddd',
    'android_id': '9774d56d682e549c',
    'lat': 37.4219999,
    'lng': -122.0840575,
    'installed_apps': ['com.bank.app', 'com.dating.app'],
    'contacts_count': 412,
  };

  /// "Sends" the event home. Returns the exact payload transmitted.
  Map<String, Object?> track(String screen) {
    final payload = buildPayload(screen);
    sent.add(payload);
    return payload;
  }
}
