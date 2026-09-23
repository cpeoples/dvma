/// PII-in-analytics helper.
///
/// INTENTIONALLY VULNERABLE (CWE-359 / CWE-200): builds analytics events that
/// carry raw PII (email, precise location, full name, device id) unfiltered,
/// instead of hashing/omitting/aggregating it. A safe pipeline would strip or
/// pseudonymize PII before it leaves the device.
///
/// The event builder is pure Dart so a unit test can assert raw PII is still
/// present in the outgoing event.
class AnalyticsEvents {
  AnalyticsEvents();

  /// Where events go (visible in mitmproxy).
  static const String endpoint = 'https://analytics.dvma.example/e';

  final List<Map<String, Object?>> sent = [];

  /// Builds a "purchase" event with raw PII attached, unfiltered.
  static Map<String, Object?> buildPurchaseEvent() => {
    'event': 'purchase',
    'amount': 42.0,
    // --- raw PII that should never be here ---
    'email': 'alice@corp.example',
    'full_name': 'Alice Q. Example',
    'lat': 37.4219999,
    'lng': -122.0840575,
    'device_id': 'a1b2c3d4-e5f6-7890-aaaa-bbbbccccdddd',
  };

  Map<String, Object?> track() {
    final e = buildPurchaseEvent();
    sent.add(e);
    return e;
  }
}
