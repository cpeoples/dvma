import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'deeplink_webview_router.dart';

/// Deep Link -> Trusted WebView Navigation.
///
/// A `url` parameter from an incoming deep link is loaded straight into a
/// trusted in-app WebView with no origin allowlist, so an attacker renders
/// arbitrary content in-app (TikTok CVE-2024-45240 / Rakuten CVE-2024-41918 /
/// EcoOnline CVE-2026-26897 class).
class DeeplinkToWebviewNavigationScreen extends StatefulWidget {
  const DeeplinkToWebviewNavigationScreen({super.key});

  static const String vulnId = 'deeplink_to_webview_navigation';

  @override
  State<DeeplinkToWebviewNavigationScreen> createState() =>
      _DeeplinkToWebviewNavigationScreenState();
}

class _DeeplinkToWebviewNavigationScreenState
    extends State<DeeplinkToWebviewNavigationScreen> {
  final TextEditingController _controller = TextEditingController(
    text: 'dvma://open?url=https://evil.example/phish',
  );

  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  WebViewController? _webController;

  @override
  void initState() {
    super.initState();
    if (supportsRealWebView) {
      _webController = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted);
    }
  }

  Future<void> _open() async {
    final deepLink = _controller.text.trim();
    final vuln = DeeplinkWebViewRouter.resolveWebViewUrl(deepLink);
    final secure = DeeplinkWebViewRouter.resolveWebViewUrlSafe(deepLink);
    // real artifact: record the attacker-controlled URL the trusted in-app
    // WebView would load from the incoming deep link (no origin allowlist).
    await DvmaEvidence.record(
      DeeplinkToWebviewNavigationScreen.vulnId,
      'webview-url',
      'deep link=$deepLink resolved into trusted WebView load url='
          '${vuln ?? '(no url param)'}',
    );
    if (!mounted) return;
    setState(() {
      _vulnResult = 'WebView would load:\n${vuln ?? '(no url param)'}';
      _secureResult = secure.allowed
          ? 'WebView would load:\n${secure.url}'
          : 'blocked - ${secure.reason}';
    });

    // On Android, actually navigate the real trusted in-app WebView to the
    // resolved url (no origin allowlist), the CVE-class sink.
    final controller = _webController;
    if (controller != null && vuln != null) {
      try {
        await controller.loadRequest(Uri.parse(vuln));
        if (!mounted) return;
        setState(
          () => _nativeResult =
              'real trusted in-app WebView navigated to $vuln (no origin '
              'allowlist; shares app session/cookies + JS bridges)',
        );
      } catch (e) {
        if (!mounted) return;
        setState(() => _nativeResult = 'native error: $e');
      }
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: DeeplinkToWebviewNavigationScreen.vulnId,
      title: 'Deep Link -> Trusted WebView Navigation',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'An incoming deep link carries a url parameter '
          '(dvma://open?url=https://evil.example/phish) that the app loads '
          'directly into a TRUSTED in-app WebView. Because there is no origin '
          'allowlist, any origin - and even javascript: / file:// URLs - is '
          'rendered inside the app\'s security context (shared session/cookies, '
          'JS bridges), enabling phishing and local-file/JS execution (the '
          'CVE-2026-26897 class). On Android the resolved URL is navigated into '
          'a REAL trusted in-app WebView (loadRequest), rendering it inside the '
          'app security context. The secure router allows only first-party https '
          'origins and rejects everything else.',
      children: [
        Padding(
          padding: const EdgeInsets.only(top: DvmaSpacing.md),
          child: TextField(
            controller: _controller,
            decoration: const InputDecoration(
              labelText: 'incoming deep link',
              hintText: 'dvma://open?url=https://evil.example/phish',
              border: OutlineInputBorder(),
            ),
          ),
        ),
        DemoActionButton(label: 'Open deep link in WebView', onPressed: _open),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'trusted WebView (no allowlist)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'origin-allowlisted WebView',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real in-app WebView navigation',
            value: _nativeResult!,
          ),
        RealWebViewView(controller: _webController),
      ],
    );
  }
}
