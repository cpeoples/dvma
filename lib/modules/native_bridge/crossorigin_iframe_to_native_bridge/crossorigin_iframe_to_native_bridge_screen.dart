import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'bridge_message_handler.dart';

/// Cross-Origin Iframe -> Native Bridge (No Main-Frame/Origin Check).
///
/// A WebView JS-bridge message handler does not verify that a message came from
/// the main frame / trusted origin, so a cross-origin iframe reaches the bridge
/// and exfiltrates the session/access token (Home Assistant Companion
/// CVE-2026-44698 class; Android addJavascriptInterface + iOS
/// WKUserContentController).
class CrossoriginIframeToNativeBridgeScreen extends StatefulWidget {
  const CrossoriginIframeToNativeBridgeScreen({super.key});

  static const String vulnId = 'crossorigin_iframe_to_native_bridge';

  @override
  State<CrossoriginIframeToNativeBridgeScreen> createState() =>
      _CrossoriginIframeToNativeBridgeScreenState();
}

class _CrossoriginIframeToNativeBridgeScreenState
    extends State<CrossoriginIframeToNativeBridgeScreen> {
  static const String _trustedOrigin = 'https://app.dvma.example';
  static const String _attackerOrigin = 'https://ads.evil.example';

  // The message the attacker's cross-origin iframe posts to the bridge.
  static const BridgeMessage _iframeMessage = BridgeMessage(
    method: 'getAccessToken',
    frame: BridgeFrame.iframe,
    origin: _attackerOrigin,
  );

  String? _vulnResult;
  String? _secureResult;

  WebViewController? _controller;
  String? _liveResult;

  @override
  void initState() {
    super.initState();
    if (!supportsRealWebView) return;
    _bootRealWebView();
  }

  /// Boots a real WebView exposing a `Bridge` channel with no frame/origin
  /// check. The main page embeds a CROSS-ORIGIN iframe (a data: document, a
  /// different origin than the app page). Android injects JS channels into ALL
  /// frames, so the iframe posts getAccessToken to the bridge and the native
  /// side hands back the token, exactly the cross-origin-iframe exfiltration.
  Future<void> _bootRealWebView() async {
    try {
      final handler = BridgeMessageHandler(trustedOrigin: _trustedOrigin);
      final controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        ..addJavaScriptChannel(
          'Bridge',
          onMessageReceived: (JavaScriptMessage m) {
            // VULN: handle any getAccessToken, regardless of frame/origin.
            if (m.message == 'getAccessToken') {
              final r = handler.handle(_iframeMessage);
              DvmaEvidence.record(
                CrossoriginIframeToNativeBridgeScreen.vulnId,
                'webview-iframe-bridge',
                'cross-origin iframe posted getAccessToken; bridge answered '
                    'without a frame/origin check -> ${r.token}',
              );
              if (!mounted) return;
              setState(
                () => _liveResult =
                    'cross-origin iframe received token: ${r.token}',
              );
            }
          },
        );
      // Main app page embeds an attacker iframe (separate origin) that calls
      // the native bridge as soon as it loads.
      const iframeDoc =
          '<html><body><script>Bridge.postMessage(%22getAccessToken%22)'
          '</script></body></html>';
      await controller.loadHtmlString(
        '<html><body><h1>app main frame</h1>'
        '<iframe src="data:text/html,$iframeDoc"></iframe>'
        '</body></html>',
      );
      if (!mounted) return;
      setState(() => _controller = controller);
    } catch (_) {
      // Best effort; helper contrast panels still demonstrate the flaw.
    }
  }

  String _render(BridgeResponse r, BridgeMessage msg) {
    final b = StringBuffer();
    b.writeln('message method   : ${msg.method}');
    b.writeln('from frame       : ${msg.frame.name}');
    b.writeln('from origin      : ${msg.origin}');
    b.writeln('trusted origin   : $_trustedOrigin');
    b.writeln('handled          : ${r.handled}');
    b.writeln('blocked          : ${r.blocked}');
    if (r.blockReason != null) {
      b.writeln('block reason     : ${r.blockReason}');
    }
    b.writeln('token returned   : ${r.token ?? '(none)'}');
    b.writeln('token exfiltrated: ${r.tokenExfiltrated(msg, _trustedOrigin)}');
    return b.toString().trimRight();
  }

  void _run() {
    final handler = BridgeMessageHandler(trustedOrigin: _trustedOrigin);

    // VULN: cross-origin iframe posts to the bridge and gets the token.
    final vuln = handler.handle(_iframeMessage);

    // SECURE: require main frame + trusted origin -> iframe refused.
    final secure = handler.handleSafe(_iframeMessage);

    setState(() {
      _vulnResult = _render(vuln, _iframeMessage);
      _secureResult = _render(secure, _iframeMessage);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: CrossoriginIframeToNativeBridgeScreen.vulnId,
      title: 'Cross-Origin Iframe -> Native Bridge',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A WebView JS-bridge message handler (Android addJavascriptInterface '
          '/ WebMessageListener; iOS WKUserContentController) is registered on '
          'the app WebView, but it does NOT verify that a message came from the '
          'MAIN FRAME or the trusted first-party origin ($_trustedOrigin). So a '
          'cross-origin ad iframe ($_attackerOrigin) embedded in the page posts '
          'a "getAccessToken" message; the native side honors it as if it were '
          'the trusted app UI and returns the session token, which the iframe '
          'exfiltrates (Home Assistant Companion CVE-2026-44698 class). This '
          'runs in a REAL WebView: a cross-origin iframe posts the message over '
          'a native JS bridge and the native side returns the token (the '
          'in-memory panel is the offline contrast). The secure path requires '
          'isMainFrame && origin==trusted before returning anything sensitive.',
      children: [
        DemoActionButton(
          label: 'Post getAccessToken from cross-origin iframe',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'bridge handler (no frame/origin check)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'validated: isMainFrame && origin==trusted',
            value: _secureResult!,
          ),
        if (_liveResult != null)
          EvidencePanel(
            label: 'REAL webview: cross-origin iframe reached the bridge',
            value: _liveResult!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
