import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'privileged_bridge.dart';

/// JS Bridge Exposes a Privileged Native API.
///
/// A bridge method exposes a privileged native capability (auth-token read,
/// Keychain/Keystore, filesystem, camera/location) to any web content with no
/// origin allowlist or permission gate, so a loaded page calls it directly
/// (Home Assistant Companion CVE-2026-44698 class).
class JsBridgeExposesPrivilegedApiScreen extends StatefulWidget {
  const JsBridgeExposesPrivilegedApiScreen({super.key});

  static const String vulnId = 'js_bridge_exposes_privileged_api';

  @override
  State<JsBridgeExposesPrivilegedApiScreen> createState() =>
      _JsBridgeExposesPrivilegedApiScreenState();
}

class _JsBridgeExposesPrivilegedApiScreenState
    extends State<JsBridgeExposesPrivilegedApiScreen> {
  static const String _attackerOrigin = 'https://ads.evil.example';

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

  /// Boots a real WebView exposing the privileged `getAuthToken` capability as
  /// an ungated `Privileged` JS channel. A loaded page (standing in for the
  /// untrusted ad origin) calls it directly and receives the Keychain token.
  Future<void> _bootRealWebView() async {
    try {
      final controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        // VULN: privileged native method exposed to ANY page, no origin gate.
        ..addJavaScriptChannel(
          'Privileged',
          onMessageReceived: (JavaScriptMessage m) async {
            if (m.message == 'getAuthToken') {
              // Read the token from a real app-private file so the value the
              // ungated bridge leaks to untrusted page JS is genuine on-disk
              // contents (adb-pullable), not a constant.
              final token = await PrivilegedBridge.readAuthTokenFromDisk();
              DvmaEvidence.record(
                JsBridgeExposesPrivilegedApiScreen.vulnId,
                'webview-privileged-bridge',
                'untrusted page called Privileged.getAuthToken() (no origin '
                    'gate) -> $token',
              );
              _controller?.runJavaScript(
                'document.title=${_jsString('token=$token')}',
              );
              if (!mounted) return;
              setState(
                () => _liveResult =
                    'page called Privileged.getAuthToken() -> $token',
              );
            }
          },
        );
      // The page auto-invokes the exposed privileged method on load.
      await controller.loadHtmlString(
        '<html><body><h1>ad frame</h1>'
        '<script>Privileged.postMessage("getAuthToken");</script>'
        '</body></html>',
      );
      if (!mounted) return;
      setState(() => _controller = controller);
    } catch (_) {
      // Best effort; helper contrast panels still demonstrate the flaw.
    }
  }

  /// Quote a Dart string as a JS string literal.
  static String _jsString(String s) =>
      '"${s.replaceAll(r'\', r'\\').replaceAll('"', r'\"')}"';

  String _render(BridgeCallResult r, Set<String> allowlist) {
    final b = StringBuffer();
    b.writeln('caller origin : $_attackerOrigin');
    b.writeln('method        : getAuthToken()');
    b.writeln('invoked       : ${r.invoked}');
    b.writeln('blocked       : ${r.blocked}');
    if (r.blockReason != null) {
      b.writeln('block reason  : ${r.blockReason}');
    }
    b.writeln('returned      : ${r.value ?? '(none)'}');
    b.writeln(
      'leaked to untrusted : '
      '${r.leakedTo(_attackerOrigin, allowlist)}',
    );
    return b.toString().trimRight();
  }

  void _run() {
    final bridge = PrivilegedBridge();

    // VULN: an untrusted ad origin calls getAuthToken() directly.
    final vuln = bridge.invoke(
      capability: BridgeCapability.readAuthToken,
      callerOrigin: _attackerOrigin,
    );

    // SECURE: origin allowlist + capability gate denies the untrusted origin.
    final secure = bridge.invokeSafe(
      capability: BridgeCapability.readAuthToken,
      callerOrigin: _attackerOrigin,
      grantedCapabilities: const {BridgeCapability.readAuthToken},
    );

    setState(() {
      _vulnResult = _render(vuln, bridge.allowedOrigins);
      _secureResult = _render(secure, bridge.allowedOrigins);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: JsBridgeExposesPrivilegedApiScreen.vulnId,
      title: 'JS Bridge Exposes a Privileged Native API',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A WebView native bridge exposes a privileged capability - reading '
          'the auth token from the Keychain/Keystore - as a plain bridge method '
          'callable by ANY loaded web content. There is no origin allowlist and '
          'no capability/permission gate, so an untrusted ad origin '
          '($_attackerOrigin) simply calls getAuthToken() and gets the token '
          '(Home Assistant Companion CVE-2026-44698 class). On a real device '
          'this runs a REAL WebView whose ungated Privileged channel reads the '
          'token from a genuine app-private file and hands it to the untrusted '
          'page; the deterministic offline model backs the contrast panels. The '
          'secure path gates every privileged method behind an origin allowlist '
          'AND a per-origin capability check, so the untrusted origin is denied '
          'before the native capability runs.',
      children: [
        DemoActionButton(
          label: 'Call getAuthToken() from untrusted ad origin',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'bridge.getAuthToken (no origin/permission gate)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'gated: origin allowlist + capability check',
            value: _secureResult!,
          ),
        if (_liveResult != null)
          EvidencePanel(
            label: 'REAL webview: page invoked Privileged.getAuthToken()',
            value: _liveResult!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
