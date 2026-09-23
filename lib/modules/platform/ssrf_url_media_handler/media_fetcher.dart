/// SSRF via URL / Media Handler helper.
///
/// INTENTIONALLY VULNERABLE (CWE-918 / CWE-601): an attacker-controlled URL
/// parameter is passed into a fetch/media loader with no allowlist and no
/// check that the destination is a public, external host. The app can therefore
/// be steered at internal/loopback/link-local endpoints (localhost, RFC1918,
/// 169.254.169.254 cloud metadata), performing requests on the attacker's
/// behalf from inside the trust boundary (WhatsApp iOS CVE-2026-23866
/// SSRF-via-URL-scheme class).
///
/// [MediaFetcher.fetchReal] opens a real socket to the caller-supplied URL, so
/// an internal/loopback/metadata request actually leaves the device and is
/// observable in mitmproxy/tcpdump. [MediaFetcher.fetch] remains a pure,
/// offline classifier (used by tests) that reports whether the request would
/// have reached an internal endpoint. The secure path ([fetchSafe]) refuses all
/// non-https / non-allowlisted (hence all internal) targets without dispatching.
library;

import 'package:http/http.dart' as http;

/// The outcome of resolving a media/url fetch request.
class FetchOutcome {
  const FetchOutcome({
    required this.requestedUrl,
    required this.dispatched,
    required this.reachedInternal,
    this.blockReason,
    this.status,
    this.firstBytes,
  });

  /// The URL the caller asked the loader to fetch.
  final String requestedUrl;

  /// Whether the loader would have actually issued the request.
  final bool dispatched;

  /// Whether the (dispatched) request targeted an internal/loopback/metadata
  /// endpoint - the SSRF hit.
  final bool reachedInternal;

  /// Why the request was refused (secure path).
  final String? blockReason;

  /// HTTP status from a real dispatched request (SSRF path), if any.
  final int? status;

  /// First bytes of the real response body (SSRF path), if any.
  final String? firstBytes;
}

class MediaFetcher {
  const MediaFetcher._();

  /// Public hosts the media loader is allowed to fetch from.
  static const Set<String> _allowedHosts = {
    'cdn.dvma.example',
    'media.dvma.example',
  };

  /// VULN: fetch whatever URL the caller supplied. No allowlist, no
  /// internal-address check - so an internal/loopback/metadata URL is happily
  /// dispatched.
  static FetchOutcome fetch(String url) {
    final uri = Uri.tryParse(url);
    final internal = uri != null && isInternalHost(uri.host);
    return FetchOutcome(
      requestedUrl: url,
      dispatched: true,
      reachedInternal: internal,
    );
  }

  /// VULN (real network): actually issue an HTTP GET to the caller-supplied URL
  /// with no allowlist and no internal-address check. A loopback/RFC1918/
  /// link-local/metadata target therefore results in a real request leaving the
  /// device from inside the trust boundary, the SSRF, observable in
  /// mitmproxy/tcpdump. Never throws; a connection error still proves the packet
  /// was dispatched (the listener/metadata host may not reply).
  static Future<FetchOutcome> fetchReal(String url) async {
    final uri = Uri.tryParse(url);
    final internal = uri != null && isInternalHost(uri.host);
    int? status;
    String? firstBytes;
    String? blockReason;
    try {
      final resp = await http
          .get(Uri.parse(url))
          .timeout(const Duration(seconds: 6));
      status = resp.statusCode;
      final body = resp.body;
      firstBytes = body.length > 200 ? '${body.substring(0, 200)}…' : body;
    } catch (e) {
      // The request still left the device; capture why no response came back.
      blockReason = 'dispatched, no response ($e)';
    }
    return FetchOutcome(
      requestedUrl: url,
      dispatched: true,
      reachedInternal: internal,
      blockReason: blockReason,
      status: status,
      firstBytes: firstBytes,
    );
  }

  /// SECURE contrast: only fetch https URLs whose host is on the public
  /// allowlist; refuse everything else (which also refuses all internal hosts).
  static FetchOutcome fetchSafe(String url) {
    final uri = Uri.tryParse(url);
    if (uri == null || uri.scheme.toLowerCase() != 'https') {
      return FetchOutcome(
        requestedUrl: url,
        dispatched: false,
        reachedInternal: false,
        blockReason: 'non-https or unparseable url',
      );
    }
    if (!_allowedHosts.contains(uri.host.toLowerCase())) {
      return FetchOutcome(
        requestedUrl: url,
        dispatched: false,
        reachedInternal: false,
        blockReason: 'host ${uri.host} not on public allowlist',
      );
    }
    return FetchOutcome(
      requestedUrl: url,
      dispatched: true,
      reachedInternal: false,
    );
  }

  /// Whether [host] is a loopback, private (RFC1918), link-local, or cloud
  /// metadata address / name.
  static bool isInternalHost(String host) {
    final h = host.toLowerCase();
    if (h == 'localhost' || h == '127.0.0.1' || h == '::1' || h == '0.0.0.0') {
      return true;
    }
    // Cloud metadata service.
    if (h == '169.254.169.254' || h == 'metadata.google.internal') {
      return true;
    }
    // Link-local 169.254.0.0/16.
    if (h.startsWith('169.254.')) return true;
    // RFC1918 private ranges.
    if (h.startsWith('10.')) return true;
    if (h.startsWith('192.168.')) return true;
    if (h.startsWith('172.')) {
      final parts = h.split('.');
      if (parts.length == 4) {
        final second = int.tryParse(parts[1]);
        if (second != null && second >= 16 && second <= 31) return true;
      }
    }
    return false;
  }
}
