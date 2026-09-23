/// WebView Cleartext / Mixed-Content Downgrade helper.
///
/// INTENTIONALLY VULNERABLE (CWE-319 / CWE-311 / CWE-757): a WebView opts OUT
/// of cleartext blocking (`usesCleartextTraffic="true"` / a relaxed
/// network-security-config) AND relaxes Mixed Content
/// (`setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)`), then loads an `http://`
/// page or a page with an `http://` subresource. A network attacker on the
/// path injects script / downgrades HTTPS->HTTP, so MITM-controlled content
/// runs in the WebView (USENIX Security 2026 HTTP-in-WebView study class).
///
/// Distinct from the app-level cleartext_traffic_allowed module (this is the
/// WebView transport + mixed-content flags) and from WebView XSS.
///
/// This is an offline + deterministic SIMULATION. [WebViewTransportLoader] has
/// `allowCleartext` + `mixedContentMode` flags. The vulnerable [load] loads an
/// http:// URL and lets a MITM-injected script / mixed-content subresource
/// execute; the secure [loadSafe] blocks cleartext and sets mixed-content to
/// BLOCK so the http load / mixed subresource is refused.
library;

/// Android WebSettings mixed-content modes.
enum MixedContentMode { block, compatibility, alwaysAllow }

/// The outcome of loading a URL under the transport config.
class TransportLoadResult {
  const TransportLoadResult({
    required this.url,
    required this.loaded,
    required this.blocked,
    required this.injectedScriptExecuted,
    required this.downgraded,
    this.exfiltratedToken,
    this.reason,
  });

  final String url;

  /// Whether the page/subresource loaded.
  final bool loaded;

  /// Whether the secure config refused the load.
  final bool blocked;

  /// Whether a MITM-injected script executed in the page.
  final bool injectedScriptExecuted;

  /// Whether an HTTPS resource was downgraded to HTTP (mixed content).
  final bool downgraded;

  /// The session token the injected script exfiltrated (vuln path).
  final String? exfiltratedToken;

  /// Why the secure config blocked.
  final String? reason;

  /// True when a MITM injection ran because cleartext/mixed content was
  /// permitted - the downgrade hit.
  bool get mitmInjected =>
      loaded && injectedScriptExecuted && exfiltratedToken != null;
}

class WebViewTransportLoader {
  const WebViewTransportLoader({
    required this.allowCleartext,
    required this.mixedContentMode,
  });

  /// `usesCleartextTraffic` / relaxed network-security-config.
  final bool allowCleartext;

  /// The WebView mixed-content mode.
  final MixedContentMode mixedContentMode;

  /// VULN config: cleartext allowed + mixed content always allowed.
  static const WebViewTransportLoader insecure = WebViewTransportLoader(
    allowCleartext: true,
    mixedContentMode: MixedContentMode.alwaysAllow,
  );

  /// SECURE config: cleartext blocked + mixed content blocked.
  static const WebViewTransportLoader secure = WebViewTransportLoader(
    allowCleartext: false,
    mixedContentMode: MixedContentMode.block,
  );

  /// An http:// page the app tries to load (a network attacker controls it).
  static const String httpUrl = 'http://app.dvma.example/dashboard';

  /// An https page whose http:// subresource the attacker injects into.
  static const String httpsUrlWithHttpSubresource =
      'https://app.dvma.example/dashboard (imports http://cdn.dvma.example/a.js)';

  /// The session token the MITM-injected script exfiltrates.
  static const String sessionToken = 'Bearer wv-71ac-session-secret';

  /// The attacker beacon (never actually contacted - simulation).
  static const String beacon = 'http://mitm.evil.example/collect';

  /// VULN: load [url]. If it is cleartext http (or an http subresource) and the
  /// config permits it, the MITM on the path injects a script that runs in the
  /// page and exfiltrates the session token.
  TransportLoadResult load(String url) {
    final isHttp = url.startsWith('http://') || url.contains('http://');
    // Cleartext http is permitted, so the MITM-served/downgraded content loads.
    if (isHttp &&
        allowCleartext &&
        mixedContentMode != MixedContentMode.block) {
      return TransportLoadResult(
        url: url,
        loaded: true,
        blocked: false,
        injectedScriptExecuted: true,
        downgraded: true,
        exfiltratedToken: sessionToken,
        reason:
            'cleartext + mixed-content allowed: MITM injected script over '
            'http and beaconed to $beacon',
      );
    }
    // An https URL with no http content loads cleanly.
    return TransportLoadResult(
      url: url,
      loaded: true,
      blocked: false,
      injectedScriptExecuted: false,
      downgraded: false,
      reason: 'https load, no cleartext content',
    );
  }

  /// SECURE contrast: cleartext is blocked and mixed content is set to BLOCK,
  /// so an http:// load or an http:// subresource on an https page is refused
  /// and no MITM content ever renders.
  TransportLoadResult loadSafe(String url) {
    final isHttp = url.startsWith('http://') || url.contains('http://');
    if (isHttp &&
        (!allowCleartext || mixedContentMode == MixedContentMode.block)) {
      return TransportLoadResult(
        url: url,
        loaded: false,
        blocked: true,
        injectedScriptExecuted: false,
        downgraded: false,
        reason:
            'cleartext blocked + mixed-content=BLOCK: http load/subresource '
            'refused',
      );
    }
    return TransportLoadResult(
      url: url,
      loaded: true,
      blocked: false,
      injectedScriptExecuted: false,
      downgraded: false,
      reason: 'https load permitted',
    );
  }
}
