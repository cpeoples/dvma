import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'webview_transport_loader.dart' hide MixedContentMode;

/// WebView Cleartext / Mixed-Content Downgrade.
///
/// A WebView opts out of cleartext blocking and relaxes mixed content, then
/// loads http/mixed content so a network attacker injects script / downgrades
/// HTTPS->HTTP (USENIX Security 2026 HTTP-in-WebView study class).
class WebviewCleartextMixedContentDowngradeScreen extends StatefulWidget {
  const WebviewCleartextMixedContentDowngradeScreen({super.key});

  static const String vulnId = 'webview_cleartext_mixed_content_downgrade';

  @override
  State<WebviewCleartextMixedContentDowngradeScreen> createState() =>
      _WebviewCleartextMixedContentDowngradeScreenState();
}

class _WebviewCleartextMixedContentDowngradeScreenState
    extends State<WebviewCleartextMixedContentDowngradeScreen> {
  String? _vulnResult;
  String? _secureResult;

  WebViewController? _controller;
  String? _liveResult;
  bool _booted = false;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (!supportsRealWebView || _booted) return;
    _booted = true;
    _bootRealWebView();
  }

  /// Boots a real WebView with MixedContentMode.ALWAYS_ALLOW and loads a real
  /// http:// (cleartext) page against the trainee's capture host, so the
  /// cleartext request is observable on the wire and a MITM could inject into
  /// it. Records the cleartext load on onPageFinished.
  Future<void> _bootRealWebView() async {
    try {
      final base = context.read<AppConfig>().captureBase;
      // Force the cleartext scheme even if captureBase is https.
      final httpBase = base.replaceFirst(RegExp('^https://'), 'http://');
      final url = '$httpBase/webview/dashboard';
      final controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        ..setNavigationDelegate(
          NavigationDelegate(
            onPageFinished: (u) {
              DvmaEvidence.record(
                WebviewCleartextMixedContentDowngradeScreen.vulnId,
                'webview-cleartext-mixed',
                'MixedContentMode=ALWAYS_ALLOW + cleartext: loaded http page '
                    'over the wire (downgradable/injectable by on-path MITM) '
                    '-> $u',
              );
              if (!mounted) return;
              setState(
                () => _liveResult = 'cleartext http load committed:\n$u',
              );
            },
          ),
        );
      // VULN: relax mixed content so cleartext http subresources/loads run.
      final platform = controller.platform;
      if (platform is AndroidWebViewController) {
        await platform.setMixedContentMode(MixedContentMode.alwaysAllow);
      }
      await controller.loadRequest(Uri.parse(url));
      if (!mounted) return;
      setState(() => _controller = controller);
    } catch (_) {
      // Best effort; helper contrast panels still demonstrate the flaw.
    }
  }

  String _render(WebViewTransportLoader loader, TransportLoadResult r) {
    final b = StringBuffer();
    b.writeln('allowCleartext     : ${loader.allowCleartext}');
    b.writeln('mixedContentMode   : ${loader.mixedContentMode.name}');
    b.writeln('url                : ${r.url}');
    b.writeln('loaded             : ${r.loaded}');
    b.writeln('downgraded to http : ${r.downgraded}');
    b.writeln('MITM script ran    : ${r.injectedScriptExecuted}');
    b.writeln('exfiltrated token  : ${r.exfiltratedToken ?? '(none)'}');
    if (r.reason != null) {
      b.writeln('reason             : ${r.reason}');
    }
    return b.toString().trimRight();
  }

  void _run() {
    const url = WebViewTransportLoader.httpUrl;

    // VULN: cleartext + mixed-content-always-allow -> MITM injection runs.
    final vuln = WebViewTransportLoader.insecure.load(url);

    // SECURE: cleartext blocked + mixed-content BLOCK -> http load refused.
    final secure = WebViewTransportLoader.secure.loadSafe(url);

    setState(() {
      _vulnResult = _render(WebViewTransportLoader.insecure, vuln);
      _secureResult = _render(WebViewTransportLoader.secure, secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: WebviewCleartextMixedContentDowngradeScreen.vulnId,
      title: 'WebView Cleartext / Mixed-Content Downgrade',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The WebView opts OUT of cleartext blocking '
          '(usesCleartextTraffic / relaxed network-security-config) AND '
          'relaxes mixed content (setMixedContentMode(MIXED_CONTENT_ALWAYS_'
          'ALLOW)), then loads an http:// page (or an http:// subresource on '
          'an https page). A network attacker on the path downgrades '
          'HTTPS->HTTP and injects a script that runs in the WebView and '
          'exfiltrates the session token (USENIX Security 2026 HTTP-in-WebView '
          'study class). This loads a real http:// page in a REAL WebView with '
          'mixed content allowed (the in-memory panel is the offline contrast). '
          'The secure path blocks cleartext and sets '
          'mixed-content to BLOCK so the http load / mixed subresource is '
          'refused.',
      children: [
        DemoActionButton(
          label: 'Load http:// dashboard in WebView',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'cleartext + mixed content allowed',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'cleartext blocked + mixed-content BLOCK',
            value: _secureResult!,
          ),
        if (_liveResult != null)
          EvidencePanel(
            label: 'REAL webview: cleartext http load (mixed=ALWAYS_ALLOW)',
            value: _liveResult!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
