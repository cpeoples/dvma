/// WebView SOP / CSP disabled helper.
///
/// INTENTIONALLY VULNERABLE (CWE-942 / CWE-346 / CWE-829): the app's WebView
/// relaxes/omits Same-Origin-Policy and Content-Security-Policy enforcement
/// (e.g. `allowUniversalAccessFromFileURLs` / `allowFileAccessFromFileURLs`
/// true, no CSP on loaded content), so a `file://` page can READ a cross-origin
/// resource AND run inline/injected script in the trusted app origin (WebKit
/// SOP-bypass CVE-2026-20643 / CSP-bypass CVE-2026-20665 app-level analog).
///
/// This is an offline, deterministic model: [WebViewEngine] models a page load against
/// a [WebViewConfig] in pure Dart. With universal-access on and no CSP, a
/// local page cross-origin-reads a remote resource and executes inline script,
/// so a session token is exfiltrated. The secure config (universal access off,
/// restrictive CSP) blocks the cross-origin read and refuses inline script.
library;

/// WebView security configuration flags.
class WebViewConfig {
  const WebViewConfig({
    required this.universalAccessFromFileUrls,
    required this.fileAccessFromFileUrls,
    required this.cspPolicy,
  });

  /// iOS `allowUniversalAccessFromFileURLs` / Android
  /// `setAllowUniversalAccessFromFileURLs`. When true a file:// page may read
  /// ANY origin (SOP disabled for file origins).
  final bool universalAccessFromFileUrls;

  /// Android `setAllowFileAccessFromFileURLs`.
  final bool fileAccessFromFileUrls;

  /// The Content-Security-Policy applied to loaded content, or null for none.
  final String? cspPolicy;

  /// VULN config: SOP relaxed for file origins, and no CSP at all.
  static const WebViewConfig insecure = WebViewConfig(
    universalAccessFromFileUrls: true,
    fileAccessFromFileUrls: true,
    cspPolicy: null,
  );

  /// SECURE config: SOP enforced for file origins, restrictive CSP that forbids
  /// inline script and cross-origin connects.
  static const WebViewConfig secure = WebViewConfig(
    universalAccessFromFileUrls: false,
    fileAccessFromFileUrls: false,
    cspPolicy: "default-src 'self'; script-src 'self'; connect-src 'self'",
  );

  /// Whether inline script is permitted under this policy. No CSP => permitted;
  /// a policy without `'unsafe-inline'` in script-src forbids it.
  bool get inlineScriptAllowed {
    final csp = cspPolicy;
    if (csp == null) return true;
    return csp.contains("'unsafe-inline'");
  }

  /// Whether a file:// page may connect to / read [targetOrigin]. Universal
  /// access overrides SOP; otherwise a restrictive connect-src blocks it.
  bool allowsCrossOriginRead(String targetOrigin) {
    if (universalAccessFromFileUrls) return true;
    final csp = cspPolicy;
    if (csp == null) return true; // no CSP => nothing stops the connect
    // Restrictive connect-src 'self' blocks any other origin.
    if (csp.contains("connect-src 'self'")) return false;
    return true;
  }
}

/// The outcome of loading a page under a config.
class WebViewLoadResult {
  const WebViewLoadResult({
    required this.crossOriginRead,
    required this.inlineScriptExecuted,
    required this.blocked,
    this.exfiltratedToken,
    this.crossOriginBody,
    this.reason,
  });

  /// Whether the local page successfully read the cross-origin resource.
  final bool crossOriginRead;

  /// Whether inline/injected script ran in the app origin.
  final bool inlineScriptExecuted;

  /// Whether the secure config blocked the attack.
  final bool blocked;

  /// The session token the inline script exfiltrated (vuln path only).
  final String? exfiltratedToken;

  /// The cross-origin body the page managed to read (vuln path only).
  final String? crossOriginBody;

  /// Why the secure config blocked (secure path only).
  final String? reason;

  /// True when the SOP/CSP failure let a secret leave the trusted origin.
  bool get tokenStolen =>
      crossOriginRead && inlineScriptExecuted && exfiltratedToken != null;
}

class WebViewEngine {
  const WebViewEngine();

  /// The app's own trusted origin (the file:// app shell).
  static const String appOrigin = 'file:///android_asset/app/index.html';

  /// A cross-origin resource holding a session token the page should not read.
  static const String crossOrigin = 'https://api.dvma.example';
  static const String crossOriginResource =
      '{"session_token":"st-6b2f-CROSS-ORIGIN-SECRET"}';
  static const String sessionToken = 'st-6b2f-CROSS-ORIGIN-SECRET';

  /// Loads the app shell under [config] and runs the (attacker-injected) inline
  /// script that tries to cross-origin-read the token and exfiltrate it.
  WebViewLoadResult load(WebViewConfig config) {
    final canRead = config.allowsCrossOriginRead(crossOrigin);
    final canRunInline = config.inlineScriptAllowed;

    if (!canRead || !canRunInline) {
      final reasons = <String>[
        if (!canRead) 'cross-origin read blocked by SOP/CSP',
        if (!canRunInline) "inline script refused (CSP has no 'unsafe-inline')",
      ];
      return WebViewLoadResult(
        crossOriginRead: canRead,
        inlineScriptExecuted: canRunInline,
        blocked: true,
        reason: reasons.join('; '),
      );
    }

    // Both SOP and CSP are effectively disabled: the page reads the remote
    // resource and the inline script exfiltrates the token.
    return const WebViewLoadResult(
      crossOriginRead: true,
      inlineScriptExecuted: true,
      blocked: false,
      crossOriginBody: crossOriginResource,
      exfiltratedToken: sessionToken,
      reason: 'universal file access + no CSP: SOP & CSP bypassed',
    );
  }
}
