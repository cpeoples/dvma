/// Cross-App Scripting helper.
///
/// INTENTIONALLY VULNERABLE (CWE-79 / CWE-749 / CWE-940): an EXPORTED activity
/// receives an attacker-controlled Intent value (a URL/JS string) from a
/// co-resident app and passes it straight to a WebView's `loadUrl()` /
/// `evaluateJavascript()` with no validation. Because the WebView is already
/// authenticated to the trusted first-party origin (cookies, tokens, DOM), any
/// injected JavaScript runs *inside that trusted origin* - Google's named
/// "Cross-App Scripting" class (Element CVE-2024-26131/26132, FireDown
/// CVE-2024-31974, TikTok CVE-2024-45240).
///
/// This is an offline + deterministic simulation. [CrossAppWebView] models a
/// tiny WebView bound to a trusted origin; it records what URL committed and
/// what JavaScript executed in which origin. It does not perform any real
/// navigation or JS execution. Tests can assert that a `javascript:` payload
/// coming off an untrusted Intent executes in the trusted origin on the vuln
/// path, and is refused on the secure path.
library;

/// A record of a script that ran inside the WebView.
class ScriptExecution {
  const ScriptExecution({
    required this.code,
    required this.origin,
    required this.trustedOrigin,
  });

  /// The JavaScript source that executed.
  final String code;

  /// The origin the script executed in.
  final String origin;

  /// Whether [origin] is the WebView's trusted first-party origin. When true
  /// for attacker-supplied code, this is the actual cross-app-scripting hit.
  final bool trustedOrigin;
}

/// The outcome of feeding an Intent value into the WebView activity.
class WebViewLoadResult {
  const WebViewLoadResult({
    required this.committedUrl,
    required this.executed,
    required this.blocked,
    this.blockReason,
  });

  /// The URL the WebView committed to (null if nothing navigated).
  final String? committedUrl;

  /// Scripts that executed as a result of this load, in order.
  final List<ScriptExecution> executed;

  /// Whether the load was refused before any attacker code could run.
  final bool blocked;

  /// Why the load was refused (secure path only).
  final String? blockReason;

  /// True if attacker-controlled JS executed in the trusted origin.
  bool get scriptedTrustedOrigin => executed.any((e) => e.trustedOrigin);
}

/// A minimal, in-memory model of a WebView bound to a trusted origin.
class CrossAppWebView {
  CrossAppWebView({required this.trustedOrigin});

  /// The origin the WebView is already authenticated to (holds the session).
  final String trustedOrigin;

  /// VULN: an exported activity handed an attacker-controlled Intent value
  /// directly to the WebView with no validation. A `javascript:` URI or an
  /// arbitrary page is loaded/evaluated in the *current* (trusted) origin, so
  /// injected JS runs with the victim's session.
  WebViewLoadResult loadFromIntent(String intentValue) {
    final executed = <ScriptExecution>[];
    if (_isJavascriptUri(intentValue)) {
      // loadUrl("javascript:...") executes in whatever origin is loaded now -
      // here the trusted first-party origin.
      executed.add(
        ScriptExecution(
          code: _stripJavascriptScheme(intentValue),
          origin: trustedOrigin,
          trustedOrigin: true,
        ),
      );
      return WebViewLoadResult(
        committedUrl: trustedOrigin,
        executed: executed,
        blocked: false,
      );
    }
    // A normal navigation: commit whatever the caller asked for. If it is a
    // remote page it still runs as its own origin, but an attacker can also
    // pass an in-origin URL with a reflected payload; model direct JS eval as
    // the sharp edge above. Here just commit the URL verbatim.
    return WebViewLoadResult(
      committedUrl: intentValue,
      executed: executed,
      blocked: false,
    );
  }

  /// SECURE contrast: validate the Intent value before touching the WebView.
  /// Reject `javascript:` (and other non-http(s)) schemes outright, and only
  /// navigate to URLs on the trusted-origin allowlist. Attacker JS never runs.
  WebViewLoadResult loadFromIntentSafe(String intentValue) {
    if (_isJavascriptUri(intentValue)) {
      return const WebViewLoadResult(
        committedUrl: null,
        executed: [],
        blocked: true,
        blockReason: 'refused non-navigational scheme (javascript:)',
      );
    }
    final uri = Uri.tryParse(intentValue);
    final scheme = uri?.scheme.toLowerCase();
    if (scheme != 'https') {
      return WebViewLoadResult(
        committedUrl: null,
        executed: const [],
        blocked: true,
        blockReason: 'refused non-https scheme (${scheme ?? 'none'})',
      );
    }
    final origin = '${uri!.scheme}://${uri.host}';
    if (origin != trustedOrigin) {
      return WebViewLoadResult(
        committedUrl: null,
        executed: const [],
        blocked: true,
        blockReason: 'origin $origin not on allowlist',
      );
    }
    return WebViewLoadResult(
      committedUrl: intentValue,
      executed: const [],
      blocked: false,
    );
  }

  static bool _isJavascriptUri(String v) =>
      v.trimLeft().toLowerCase().startsWith('javascript:');

  static String _stripJavascriptScheme(String v) {
    final t = v.trimLeft();
    return t.substring('javascript:'.length);
  }
}
