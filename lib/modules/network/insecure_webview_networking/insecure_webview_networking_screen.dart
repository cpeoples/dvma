import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Insecure WebView Networking.
///
/// WebView ignores network security config and loads mixed/cleartext content.
class InsecureWebviewNetworkingScreen extends StatefulWidget {
  const InsecureWebviewNetworkingScreen({super.key});

  static const String vulnId = 'insecure_webview_networking';

  @override
  State<InsecureWebviewNetworkingScreen> createState() =>
      _InsecureWebviewNetworkingScreenState();
}

class _InsecureWebviewNetworkingScreenState
    extends State<InsecureWebviewNetworkingScreen> {
  // VULN: the WebView allows mixed content and loads over cleartext http://.
  // An https page could pull http:// scripts (injectable by an on-path
  // attacker). Here we use a webview_flutter controller with mixed content
  // ALWAYS_ALLOW and load a real http:// page, the request is visible to a
  // proxy/on-path attacker.
  late final WebViewController _controller;
  late final String _url;
  String? _status;

  @override
  void initState() {
    super.initState();
    _url = '${context.read<AppConfig>().captureBase}/webview';
    _controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setNavigationDelegate(
        NavigationDelegate(
          onPageFinished: (u) => _report('loaded $u'),
          onWebResourceError: (e) =>
              _report('resource error: ${e.description}'),
        ),
      );
    // MIXED_CONTENT_ALWAYS_ALLOW on Android: allow the cleartext load.
    final platform = _controller.platform;
    if (platform is AndroidWebViewController) {
      platform.setMixedContentMode(MixedContentMode.alwaysAllow);
    }
  }

  void _report(String s) {
    DvmaEvidence.record(
      InsecureWebviewNetworkingScreen.vulnId,
      'webview-cleartext',
      'GET $_url via WebView (mixedContent=ALWAYS_ALLOW) -> $s',
    );
    if (!mounted) return;
    setState(() => _status = s);
  }

  void _load() {
    setState(() => _status = 'loading $_url …');
    _controller.loadRequest(Uri.parse(_url));
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: InsecureWebviewNetworkingScreen.vulnId,
      title: 'Insecure WebView Networking',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The embedded WebView enables mixed content and loads a real http:// '
          'page. An on-path attacker (or your proxy) sees the cleartext request '
          'and can inject JavaScript into the response. The load below is a '
          'webview_flutter request against your capture host.',
      children: [
        EvidencePanel(
          label: 'webview settings',
          value: PlatformLingo.current().isIOS
              ? 'WKWebView: no ATS exception enforced (cleartext http:// '
                    'permitted)\nurl = $_url'
              : 'mixedContentMode = ALWAYS_ALLOW\nurl = $_url',
        ),
        DemoActionButton(label: 'Load page', onPressed: _load),
        if (_status != null)
          EvidencePanel(label: 'load status', value: _status!),
        const SizedBox(height: 12),
        SizedBox(
          height: 220,
          child: DecoratedBox(
            decoration: BoxDecoration(
              border: Border.all(color: Colors.white24),
            ),
            child: WebViewWidget(controller: _controller),
          ),
        ),
      ],
    );
  }
}
