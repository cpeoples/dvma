/// WebView URL-Loading Policy Confusion helper.
///
/// INTENTIONALLY VULNERABLE (CWE-20 / CWE-441 / CWE-939): the WebView's
/// navigation-policy handler (`shouldOverrideUrlLoading` on Android /
/// `decidePolicyForNavigationAction` on iOS) makes an allow/deny trust decision
/// on a RAW, un-canonicalized URL string. Because it only does a naive
/// substring/prefix check against the intended host, scheme and host confusion
/// slips through: `javascript:` (script execution), `file:///` (local file
/// exfiltration), `content://` (privileged provider), a look-alike subdomain
/// (`app.example.evil.com`), or the genuine host smuggled into a query/path of
/// an attacker origin (`https://evil/?x=app.example`). The bug is the POLICY
/// IMPLEMENTATION, not the call to loadUrl (MASTG-TEST-0332 class).
///
/// This is an offline + deterministic SIMULATION. [UrlLoadingPolicy] decides
/// allow/deny for a navigation URL against an intended allowlist (https on one
/// exact host). The vulnerable [shouldOverride] does a naive `contains` check
/// that the crafted URLs bypass; the secure [shouldOverrideSafe] canonicalizes
/// and parses the URL, then allowlists scheme (https only) AND exact host,
/// rejecting the crafted URLs while still allowing the genuine one.
library;

/// The outcome of a navigation-policy decision for a single URL.
class UrlPolicyDecision {
  const UrlPolicyDecision({
    required this.url,
    required this.loaded,
    required this.policyBypassed,
    this.denyReason,
  });

  final String url;

  /// Whether the navigation was allowed to load.
  final bool loaded;

  /// Whether a URL that should have been denied was allowed - the hit.
  final bool policyBypassed;

  /// Why the secure policy denied the navigation.
  final String? denyReason;
}

class UrlLoadingPolicy {
  const UrlLoadingPolicy();

  /// The only scheme the app intends to load.
  static const String allowedScheme = 'https';

  /// The only host the app intends to load.
  static const String allowedHost = 'app.example';

  /// The genuine, in-scope URL that must always be allowed.
  static const String genuineUrl = 'https://app.example/account';

  /// Crafted URLs that a naive policy check lets through but that must be
  /// denied: script execution, local file read, privileged provider, a
  /// look-alike subdomain, the host smuggled into a query, and a bare
  /// case/whitespace trick.
  static const List<String> craftedBypassUrls = <String>[
    'javascript:alert(document.cookie)',
    'file:///data/data/com.dvma.app/databases/secrets.db',
    'content://com.dvma.app.provider/private/session',
    'https://app.example.evil.com/account',
    'https://evil.example/?next=app.example',
    'HtTpS://app.example.evil.com/account',
  ];

  /// VULN: naive trust decision on the raw URL. Any URL merely CONTAINING the
  /// intended host substring is treated as in-scope and loaded, so every
  /// crafted URL above bypasses the check. `javascript:`/`file:`/`content:`
  /// URLs that don't even mention the host are also loaded because the handler
  /// returns false (do-not-override -> WebView loads it) for anything it does
  /// not explicitly recognize.
  UrlPolicyDecision shouldOverride(String url) {
    final looksInScope = url.contains(allowedHost);
    if (looksInScope) {
      // Treated as our own host -> loaded even though scheme/host are wrong.
      return UrlPolicyDecision(
        url: url,
        loaded: true,
        policyBypassed: !_isGenuinelyInScope(url),
      );
    }
    // Unrecognized scheme (javascript:/file:/content:) -> handler does not
    // override, so the WebView loads the privileged URL anyway.
    return UrlPolicyDecision(url: url, loaded: true, policyBypassed: true);
  }

  /// SECURE contrast: canonicalize + parse the URL, then allow only when the
  /// scheme is https AND the host is an exact match for the intended host.
  /// Everything else (other schemes, look-alike subdomains, host-in-query,
  /// malformed URLs) is denied.
  UrlPolicyDecision shouldOverrideSafe(String url) {
    final canonical = url.trim();
    final uri = Uri.tryParse(canonical);
    if (uri == null || !uri.hasScheme) {
      return UrlPolicyDecision(
        url: url,
        loaded: false,
        policyBypassed: false,
        denyReason: 'unparseable/relative URL rejected',
      );
    }
    final scheme = uri.scheme.toLowerCase();
    if (scheme != allowedScheme) {
      return UrlPolicyDecision(
        url: url,
        loaded: false,
        policyBypassed: false,
        denyReason: 'scheme "$scheme" not allowlisted (https only)',
      );
    }
    final host = uri.host.toLowerCase();
    if (host != allowedHost) {
      return UrlPolicyDecision(
        url: url,
        loaded: false,
        policyBypassed: false,
        denyReason: 'host "$host" is not an exact match for $allowedHost',
      );
    }
    // https + exact host: genuinely in-scope.
    return UrlPolicyDecision(
      url: url,
      loaded: true,
      policyBypassed: false,
      denyReason: null,
    );
  }

  /// A strict, canonicalized in-scope check used to label the vuln result.
  bool _isGenuinelyInScope(String url) {
    final uri = Uri.tryParse(url.trim());
    if (uri == null) return false;
    return uri.scheme.toLowerCase() == allowedScheme &&
        uri.host.toLowerCase() == allowedHost;
  }
}
