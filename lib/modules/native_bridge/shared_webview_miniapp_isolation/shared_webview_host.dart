/// Shared-WebView Mini-App isolation-failure helper.
///
/// INTENTIONALLY VULNERABLE (CWE-1188 / CWE-668 / CWE-200): a super-app hosts
/// multiple mini-programs in ONE shared WebView instance with a SINGLE shared
/// cookie jar / localStorage keyed loosely (not partitioned per mini-app
/// origin). So mini-app A simply reads mini-app B's cookies and storage - a
/// cross-tenant isolation failure enabling data exfiltration between mini-apps
/// (WeChat / Alipay / TikTok / Baidu cross-mini-program cookie-sharing
/// research class).
///
/// This is an offline, deterministic model: [SharedWebViewHost] models a single shared
/// store plus a partitioned store in pure Dart. The vuln path writes mini-app
/// B's cookie into the shared jar and lets mini-app A read it back. The secure
/// path partitions storage per mini-app origin, so A cannot see B's cookie.
library;

/// The outcome of a mini-app storage read.
class StorageReadResult {
  const StorageReadResult({
    required this.granted,
    required this.blocked,
    this.value,
    this.reason,
  });

  /// Whether a value was returned to the reader.
  final bool granted;

  /// Whether the partitioned store refused the cross-tenant read.
  final bool blocked;

  /// The value read (the victim's cookie on the vuln path).
  final String? value;

  /// Why the read was refused / how it was served.
  final String? reason;

  /// True when [reader] obtained a value belonging to a DIFFERENT mini-app -
  /// the cross-tenant leak.
  bool crossTenantLeak(String reader, String owner) =>
      granted && value != null && reader != owner;
}

class SharedWebViewHost {
  SharedWebViewHost();

  static const String miniAppA = 'https://mini-a.super.example';
  static const String miniAppB = 'https://mini-b.super.example';

  /// A high-value cookie belonging to mini-app B (a session/pay token).
  static const String cookieName = 'session';
  static const String miniBCookie = 'sid-B-9f2a-PAY-TOKEN';

  /// VULN: ONE shared cookie jar for every mini-app, keyed only by cookie name.
  /// There is no per-origin partition, so whoever writes/reads a name wins.
  final Map<String, String> _sharedJar = {};

  /// SECURE: cookies partitioned per mini-app origin: origin -> (name -> value).
  final Map<String, Map<String, String>> _partitionedJar = {};

  /// Mini-app B stores its cookie. On the vuln path it lands in the shared jar;
  /// on the secure path it lands in B's private partition.
  void storeCookie({
    required String origin,
    required String name,
    required String value,
    required bool partitioned,
  }) {
    if (partitioned) {
      (_partitionedJar[origin] ??= {})[name] = value;
    } else {
      _sharedJar[name] = value;
    }
  }

  /// VULN: [reader] reads a cookie by name out of the single shared jar. It
  /// gets whatever any mini-app wrote there - including another tenant's.
  StorageReadResult readCookie({
    required String readerOrigin,
    required String name,
  }) {
    final value = _sharedJar[name];
    return StorageReadResult(
      granted: value != null,
      blocked: false,
      value: value,
      reason: 'read from single shared jar (no per-origin partition)',
    );
  }

  /// SECURE contrast: [reader] can only read cookies from ITS own partition. A
  /// cross-tenant read returns nothing.
  StorageReadResult readCookieSafe({
    required String readerOrigin,
    required String name,
  }) {
    final value = _partitionedJar[readerOrigin]?[name];
    if (value == null) {
      return StorageReadResult(
        granted: false,
        blocked: true,
        reason:
            'no cookie "$name" in partition for $readerOrigin '
            '(cross-tenant read blocked)',
      );
    }
    return StorageReadResult(
      granted: true,
      blocked: false,
      value: value,
      reason: 'served from own partition',
    );
  }
}
