/// In-App Browser UI / Address-Bar Spoofing helper.
///
/// INTENTIONALLY VULNERABLE (CWE-1021 / CWE-451): an in-app WebView browser
/// derives the origin shown in its address bar from ATTACKER-CONTROLLABLE page
/// content (e.g. `document.title`, a `pushState` path, or a `data:`/`about:`
/// trick) instead of the real committed URL. The chrome therefore displays a
/// trusted origin (`https://bank.example`) while the page actually loaded is
/// the attacker's (`https://evil.example`), enabling website spoofing / UI
/// misrepresentation. This is the Firefox Focus CVE-2025-10290 / LINE
/// CVE-2024-5739 trust class.
///
/// This is an offline + deterministic simulation: a [BrowserPage] carries the
/// real committed URL alongside the attacker-claimed origin, and the address
/// bar is just a computed string (no real WebView). A test can assert the
/// vulnerable address bar shows the spoofed origin (shown != actual) while the
/// safe one always shows the true committed origin (eTLD+1).
class InAppBrowserModel {
  InAppBrowserModel._();

  /// VULN: the address bar reflects the attacker-claimed origin taken from
  /// page-controlled content. If the page claims an origin, that string is
  /// shown verbatim, even though the committed URL is something else.
  static AddressBar displayedAddressBar(BrowserPage page) {
    final shown = (page.claimedOrigin != null && page.claimedOrigin!.isNotEmpty)
        ? page.claimedOrigin!
        : _origin(page.committedUrl);
    final actual = _origin(page.committedUrl);
    return AddressBar(shown: shown, actual: actual, spoofed: shown != actual);
  }

  /// SECURE contrast: always derive the address bar from the real committed
  /// URL's origin (scheme + eTLD+1 host), ignoring any page-supplied claim.
  static AddressBar displayedAddressBarSafe(BrowserPage page) {
    final actual = _origin(page.committedUrl);
    return AddressBar(shown: actual, actual: actual, spoofed: false);
  }

  /// Reduce a URL to a displayable origin (scheme://host). Non-http(s) or
  /// unparseable URLs fall back to a clearly non-trusted marker.
  static String _origin(String url) {
    final uri = Uri.tryParse(url);
    if (uri == null || uri.host.isEmpty) {
      return url; // e.g. data:/about:, surfaced as-is, never a trusted host
    }
    return '${uri.scheme}://${uri.host}';
  }
}

/// A simulated navigation: the URL the WebView actually committed to, plus an
/// attacker-controllable origin the page tries to claim in the chrome.
class BrowserPage {
  const BrowserPage({required this.committedUrl, this.claimedOrigin});

  /// The real URL the WebView loaded/committed.
  final String committedUrl;

  /// An origin claimed by page-controlled content (document.title, pushState,
  /// data:/about: trick). Null when the page makes no claim.
  final String? claimedOrigin;
}

/// What the browser chrome renders vs. reality.
class AddressBar {
  const AddressBar({
    required this.shown,
    required this.actual,
    required this.spoofed,
  });

  /// The origin displayed in the address bar to the user.
  final String shown;

  /// The real committed origin.
  final String actual;

  /// Whether the shown origin misrepresents the real one.
  final bool spoofed;
}
