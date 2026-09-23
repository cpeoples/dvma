import 'dart:io';

/// Accept-all TrustManager helper.
///
/// INTENTIONALLY VULNERABLE (CWE-295): installs a certificate callback that
/// returns `true` for ANY certificate, disabling TLS validation entirely. This
/// is the Dart/Flutter equivalent of an Android `X509TrustManager` whose
/// `checkServerTrusted` does nothing, it makes MITM with a self-signed cert
/// trivial (Burp/mitmproxy just work).
///
/// The callback is exposed on its own so a unit test can assert it still
/// blindly trusts a bogus cert.
class AcceptAllTrust {
  AcceptAllTrust._();

  /// The insecure callback: trusts every certificate, for every host.
  static bool acceptAny(X509Certificate cert, String host, int port) => true;

  /// Convenience for demos/tests: the policy decision with no cert instance
  /// needed. Always true, that is the vulnerability.
  static bool trustsEverything() => true;

  /// Returns an HttpClient with validation disabled (do not ship this).
  static HttpClient insecureClient() {
    final client = HttpClient();
    client.badCertificateCallback = acceptAny;
    return client;
  }

  /// Performs an HTTPS GET against [url] with certificate validation
  /// disabled, so a mitmproxy self-signed cert is accepted end-to-end. Returns
  /// a short one-line summary of the connection (or the error). Never throws.
  static Future<String> fetchIgnoringCerts(String url) async {
    final client = insecureClient();
    try {
      final req = await client.getUrl(Uri.parse(url));
      final resp = await req.close().timeout(const Duration(seconds: 6));
      final cert = resp.certificate;
      final subject = cert?.subject ?? '(none)';
      return 'GET $url -> HTTP ${resp.statusCode}; '
          'server cert subject=$subject ACCEPTED (validation disabled)';
    } catch (e) {
      final s = e.toString();
      return 'GET $url -> ${s.length <= 100 ? s : '${s.substring(0, 97)}...'}';
    } finally {
      client.close(force: true);
    }
  }
}
