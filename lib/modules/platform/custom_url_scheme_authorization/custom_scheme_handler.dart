/// Custom URL Scheme Authorization helper.
///
/// INTENTIONALLY VULNERABLE (CWE-939 / CWE-862 / CWE-601): the app registers a
/// custom URL scheme (e.g. `dvma://open?url=...`) and its handler loads the
/// caller-supplied `url` parameter WITHOUT checking who invoked it and WITHOUT
/// an allowlist. Any co-resident app can therefore fire the scheme and make
/// DVMA display an attacker-controlled site inside its trusted chrome (Rakuten
/// CVE-2024-41918 / @cosme CVE-2024-45203 / Skylark CVE-2024-54014 / Groww
/// CVE-2026-12065 class).
///
/// This is an offline + deterministic simulation. [CustomSchemeHandler] models
/// the deep-link handler and returns what URL it would display and whether it
/// left the trusted app context. Tests can assert an attacker URL is displayed
/// on the vuln path and refused on the secure path (scheme + host allowlist).
library;

/// The outcome of handling a custom-scheme deep link.
class SchemeHandleResult {
  const SchemeHandleResult({
    required this.displayedUrl,
    required this.blocked,
    this.blockReason,
  });

  /// The URL the handler actually loaded/displayed (null if refused).
  final String? displayedUrl;

  /// Whether the deep link was refused before anything was displayed.
  final bool blocked;

  final String? blockReason;

  /// True if a URL outside the trusted-host allowlist was displayed.
  bool get displayedUntrusted =>
      !blocked &&
      displayedUrl != null &&
      !CustomSchemeHandler.isTrustedUrl(displayedUrl!);
}

class CustomSchemeHandler {
  const CustomSchemeHandler._();

  /// Hosts the app is willing to render in its trusted chrome.
  static const Set<String> _trustedHosts = {
    'app.dvma.example',
    'help.dvma.example',
  };

  /// VULN: pull the `url` query param off the incoming deep link and load it
  /// directly. No caller check, no allowlist - whatever an untrusted app put
  /// in the parameter is displayed.
  static SchemeHandleResult handle(String deepLink) {
    final target = _extractUrlParam(deepLink);
    return SchemeHandleResult(displayedUrl: target, blocked: false);
  }

  /// SECURE contrast: only display the target when it is an https URL on the
  /// trusted-host allowlist; refuse everything else.
  static SchemeHandleResult handleSafe(String deepLink) {
    final target = _extractUrlParam(deepLink);
    if (target == null) {
      return const SchemeHandleResult(
        displayedUrl: null,
        blocked: true,
        blockReason: 'no url parameter',
      );
    }
    if (!isTrustedUrl(target)) {
      return SchemeHandleResult(
        displayedUrl: null,
        blocked: true,
        blockReason: 'url not on trusted-host allowlist: $target',
      );
    }
    return SchemeHandleResult(displayedUrl: target, blocked: false);
  }

  /// Whether [url] is an https URL on the trusted-host allowlist.
  static bool isTrustedUrl(String url) {
    final uri = Uri.tryParse(url);
    if (uri == null) return false;
    if (uri.scheme.toLowerCase() != 'https') return false;
    return _trustedHosts.contains(uri.host.toLowerCase());
  }

  static String? _extractUrlParam(String deepLink) {
    final uri = Uri.tryParse(deepLink);
    if (uri == null) return null;
    return uri.queryParameters['url'];
  }
}
