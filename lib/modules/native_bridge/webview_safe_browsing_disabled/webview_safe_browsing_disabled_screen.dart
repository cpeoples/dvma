import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'safe_browsing_webview.dart';

/// WebView Safe Browsing Disabled.
///
/// The WebView disables Google Safe Browsing, so navigation to a known
/// phishing/malware URL loads with no interstitial warning.
class WebviewSafeBrowsingDisabledScreen extends StatefulWidget {
  const WebviewSafeBrowsingDisabledScreen({super.key});

  static const String vulnId = 'webview_safe_browsing_disabled';

  @override
  State<WebviewSafeBrowsingDisabledScreen> createState() =>
      _WebviewSafeBrowsingDisabledScreenState();
}

class _WebviewSafeBrowsingDisabledScreenState
    extends State<WebviewSafeBrowsingDisabledScreen> {
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

  /// Boots a real WebView and navigates to a known-bad-shaped phishing URL
  /// (routed to the trainee's capture host so the request is observable). With
  /// Safe Browsing disabled via the AndroidManifest meta-data, the navigation
  /// proceeds with no interstitial, recorded on onPageFinished.
  Future<void> _bootRealWebView() async {
    try {
      final base = context.read<AppConfig>().captureBase;
      // A phishing-shaped path hitting the capture listener (no real bad host
      // is contacted; the point is that no interstitial blocked the load).
      final url = '$base/phishing/secure-login.paypa1-verify';
      final controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        ..setNavigationDelegate(
          NavigationDelegate(
            onPageFinished: (u) {
              DvmaEvidence.record(
                WebviewSafeBrowsingDisabledScreen.vulnId,
                'webview-safe-browsing',
                'Safe Browsing disabled (manifest EnableSafeBrowsing=false): '
                    'phishing-shaped URL loaded with no interstitial -> $u',
              );
              if (!mounted) return;
              setState(
                () => _liveResult =
                    'loaded with NO Safe Browsing interstitial:\n$u',
              );
            },
          ),
        );
      await controller.loadRequest(Uri.parse(url));
      if (!mounted) return;
      setState(() => _controller = controller);
    } catch (_) {
      // Best effort; helper contrast panels still demonstrate the flaw.
    }
  }

  String _render(SafeBrowsingNavResult r) {
    final b = StringBuffer();
    b.writeln('safeBrowsingEnabled : ${r.safeBrowsingEnabled}');
    b.writeln('url                 : ${r.url}');
    b.writeln('known-bad host      : ${r.isKnownBad}');
    b.writeln('loaded              : ${r.loaded}');
    b.writeln('threat blocked      : ${r.threatBlocked}');
    b.writeln('malicious unwarned  : ${r.maliciousPageLoadedUnwarned}');
    if (r.denyReason != null) {
      b.writeln('deny reason         : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  void _run() {
    const url = SafeBrowsingWebView.knownBadUrl;

    // VULN: Safe Browsing disabled -> known-bad URL loads with no warning.
    final vuln = SafeBrowsingWebView.insecure.navigate(url);

    // SECURE: Safe Browsing on -> known-bad URL is blocked by interstitial.
    final secure = SafeBrowsingWebView.secure.navigateSafe(url);

    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: WebviewSafeBrowsingDisabledScreen.vulnId,
      title: 'WebView Safe Browsing Disabled',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'The WebView turns OFF Google Safe Browsing '
          '(setSafeBrowsingEnabled(false) / manifest EnableSafeBrowsing='
          'false), stripping the browser-originated malware/phishing '
          'protection that normally shows a full-page interstitial before a '
          'known-bad navigation. With it disabled, the app silently loads a '
          'known phishing/malware URL with no warning. This is NOT XSS - it is '
          'a deliberately removed platform protection (Android WebView '
          'MASTG-TEST-0399 class). This navigates a REAL WebView to the '
          'known-bad URL (the in-memory panel is the offline contrast). The '
          'secure path keeps Safe '
          'Browsing on, blocks known-bad hosts with an interstitial, and still '
          'allows benign URLs.',
      children: [
        DemoActionButton(label: 'Navigate to known-bad URL', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'safe browsing disabled: malicious page loaded',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'safe browsing on: interstitial blocked navigation',
            value: _secureResult!,
          ),
        if (_liveResult != null)
          EvidencePanel(
            label: 'REAL webview: known-bad URL loaded unwarned',
            value: _liveResult!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
