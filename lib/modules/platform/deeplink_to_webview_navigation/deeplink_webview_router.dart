/// Deep Link -> Trusted WebView Navigation helper.
///
/// INTENTIONALLY VULNERABLE (CWE-939 / CWE-601): an incoming deep link carries
/// a `url` parameter (e.g. `dvma://open?url=https://evil.example/phish`) that
/// the app loads straight into a TRUSTED, in-app WebView with no origin
/// allowlist. Because the WebView is trusted (shares cookies/session, may have
/// JS bridges), an attacker who can trigger the deep link renders arbitrary
/// content - including `javascript:` and `file://` URLs - inside the app's
/// security context (the TikTok CVE-2024-45240 / Rakuten CVE-2024-41918 /
/// EcoOnline CVE-2026-26897 class).
///
/// This is an offline + deterministic simulation of the real mechanism: instead
/// of instantiating a real WebView we simply resolve and return the URL that
/// WOULD be loaded, so a test can assert the vulnerable router returns the
/// attacker origin while [resolveWebViewUrlSafe] rejects it.
class DeeplinkWebViewRouter {
  DeeplinkWebViewRouter._();

  /// First-party https origins the app actually trusts to render in-WebView.
  static const Set<String> allowedOrigins = {
    'https://app.dvma.example',
    'https://help.dvma.example',
  };

  /// Extracts the `url` query parameter from a `dvma://open?url=...` deep link.
  static String? _extractUrlParam(String deepLink) {
    final uri = Uri.tryParse(deepLink);
    if (uri == null) return null;
    return uri.queryParameters['url'];
  }

  /// VULN: pull the `url` param out of the deep link and return it verbatim as
  /// the URL to load in the trusted WebView. No scheme check, no origin
  /// allowlist - so `https://evil.example`, `javascript:...`, and `file://...`
  /// all pass straight through.
  static String? resolveWebViewUrl(String deepLink) {
    return _extractUrlParam(deepLink);
  }

  /// SECURE contrast: only allow first-party https origins. Anything else
  /// (other origins, `javascript:`, `file://`, malformed) is rejected and the
  /// WebView is never navigated.
  static WebViewDecision resolveWebViewUrlSafe(String deepLink) {
    final url = _extractUrlParam(deepLink);
    if (url == null || url.isEmpty) {
      return const WebViewDecision(
        url: null,
        allowed: false,
        reason: 'rejected: no url parameter',
      );
    }
    final target = Uri.tryParse(url);
    if (target == null || target.scheme.toLowerCase() != 'https') {
      return WebViewDecision(
        url: null,
        allowed: false,
        reason: 'rejected: non-https scheme (${target?.scheme ?? 'invalid'})',
      );
    }
    final origin = '${target.scheme}://${target.host}';
    if (!allowedOrigins.contains(origin)) {
      return WebViewDecision(
        url: null,
        allowed: false,
        reason: 'rejected: origin not on first-party allowlist ($origin)',
      );
    }
    return WebViewDecision(url: url, allowed: true, reason: 'allowed origin');
  }
}

/// Outcome of the secure WebView navigation decision.
class WebViewDecision {
  const WebViewDecision({
    required this.url,
    required this.allowed,
    required this.reason,
  });

  /// The URL the WebView would load, or null when rejected.
  final String? url;

  /// Whether the navigation is permitted.
  final bool allowed;

  /// Human-readable explanation of the decision.
  final String reason;
}
