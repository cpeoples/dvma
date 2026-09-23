/// WebView Safe Browsing Disabled helper.
///
/// INTENTIONALLY VULNERABLE (CWE-1188 / CWE-693 / CWE-829): an embedded WebView
/// turns OFF Google Safe Browsing (`WebSettingsCompat.setSafeBrowsingEnabled(
/// false)` or manifest `<meta-data android:name=
/// "android.webkit.WebView.EnableSafeBrowsing" android:value="false"/>`). Safe
/// Browsing is a browser-originated defense that shows a full-page interstitial
/// before navigation to known malware/phishing hosts. Removing it means the app
/// silently loads attacker-controlled known-bad URLs with no warning.
///
/// Distinct from XSS: nothing is being injected here. The app deliberately
/// STRIPS a platform protection from its own browser surface (Android WebView
/// MASTG-TEST-0399 class).
///
/// This is an offline + deterministic SIMULATION. [SafeBrowsingWebView] holds a
/// `safeBrowsingEnabled` flag and a set of known-bad hosts. The vulnerable
/// [navigate] loads any URL with no interstitial; the secure [navigateSafe]
/// keeps Safe Browsing on, blocks known-bad URLs with a warning, and still
/// allows benign URLs through.
library;

/// The outcome of navigating the WebView to a URL under a Safe Browsing config.
class SafeBrowsingNavResult {
  const SafeBrowsingNavResult({
    required this.url,
    required this.loaded,
    required this.safeBrowsingEnabled,
    required this.threatBlocked,
    required this.isKnownBad,
    this.denyReason,
  });

  final String url;

  /// Whether the page actually loaded in the WebView.
  final bool loaded;

  /// Whether Safe Browsing was active for this navigation.
  final bool safeBrowsingEnabled;

  /// Whether a known-bad URL was stopped by an interstitial/deny.
  final bool threatBlocked;

  /// Whether the target is on the known malware/phishing list.
  final bool isKnownBad;

  /// Why the secure path refused the navigation.
  final String? denyReason;

  /// True when a known-bad URL was loaded with no protection - the hit.
  bool get maliciousPageLoadedUnwarned =>
      loaded && isKnownBad && !threatBlocked;
}

class SafeBrowsingWebView {
  const SafeBrowsingWebView({required this.safeBrowsingEnabled});

  /// Whether the WebView keeps Google Safe Browsing on for navigations.
  final bool safeBrowsingEnabled;

  /// VULN config: Safe Browsing explicitly disabled.
  static const SafeBrowsingWebView insecure = SafeBrowsingWebView(
    safeBrowsingEnabled: false,
  );

  /// SECURE config: Safe Browsing left on (the platform default).
  static const SafeBrowsingWebView secure = SafeBrowsingWebView(
    safeBrowsingEnabled: true,
  );

  /// A known phishing/malware URL (deterministic, never actually contacted).
  static const String knownBadUrl =
      'http://secure-login.paypa1-verify.example/account';

  /// A legitimate benign URL that should always load.
  static const String benignUrl = 'https://app.dvma.example/dashboard';

  /// Hosts Safe Browsing recognizes as malware/phishing.
  static const Set<String> knownBadHosts = <String>{
    'secure-login.paypa1-verify.example',
    'malware.evil.example',
  };

  static String? _hostOf(String url) => Uri.tryParse(url)?.host;

  static bool _isKnownBad(String url) {
    final host = _hostOf(url);
    return host != null && knownBadHosts.contains(host);
  }

  /// VULN: navigate to [url]. With Safe Browsing disabled the WebView performs
  /// no reputation check, so a known-phishing/malware page loads with no
  /// interstitial warning.
  SafeBrowsingNavResult navigate(String url) {
    final bad = _isKnownBad(url);
    // Safe Browsing off: every URL loads, malicious or not, with no warning.
    return SafeBrowsingNavResult(
      url: url,
      loaded: true,
      safeBrowsingEnabled: safeBrowsingEnabled,
      threatBlocked: false,
      isKnownBad: bad,
      denyReason: null,
    );
  }

  /// SECURE contrast: keep Safe Browsing on. Known-bad URLs are stopped with an
  /// interstitial (not loaded); benign URLs load normally.
  SafeBrowsingNavResult navigateSafe(String url) {
    final bad = _isKnownBad(url);
    if (bad) {
      return SafeBrowsingNavResult(
        url: url,
        loaded: false,
        safeBrowsingEnabled: true,
        threatBlocked: true,
        isKnownBad: true,
        denyReason:
            'Safe Browsing interstitial: host is a known '
            'phishing/malware site; navigation blocked',
      );
    }
    return SafeBrowsingNavResult(
      url: url,
      loaded: true,
      safeBrowsingEnabled: true,
      threatBlocked: false,
      isKnownBad: false,
      denyReason: null,
    );
  }
}
