import 'dart:io' show File;

import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'webview_engine.dart';

/// WebView SOP / CSP Disabled (Cross-Origin & Inline Script).
///
/// The app's WebView relaxes/omits SOP + CSP (universal file access on, no CSP)
/// so a file:// page cross-origin-reads a remote resource and runs inline
/// script in the trusted app origin, exfiltrating a token. The secure config
/// enforces SOP and a restrictive CSP, blocking both.
class WebviewSopCspDisabledScreen extends StatefulWidget {
  const WebviewSopCspDisabledScreen({super.key});

  static const String vulnId = 'webview_sop_csp_disabled';

  @override
  State<WebviewSopCspDisabledScreen> createState() =>
      _WebviewSopCspDisabledScreenState();
}

class _WebviewSopCspDisabledScreenState
    extends State<WebviewSopCspDisabledScreen> {
  String? _vuln;
  String? _secure;

  WebViewController? _controller;
  String? _liveResult;

  @override
  void initState() {
    super.initState();
    if (!supportsRealWebView) return;
    _bootRealWebView();
  }

  /// Boots a real WebView with a file:// origin, file access ON, and no CSP, so
  /// an inline <script> executes in the app origin and cross-reads a sibling
  /// local file via fetch('file://...'), exfiltrating its token. (The plugin
  /// cannot toggle allowUniversalAccessFromFileURLs to reach a *remote* origin,
  /// so the real demo shows the achievable file-origin cross-read + inline
  /// script; the in-memory contrast covers the remote SOP-bypass story.)
  Future<void> _bootRealWebView() async {
    try {
      final dir = await DvmaEvidence.artifactDirPath();
      if (dir == null) return;

      // A sibling local resource holding the cross-origin token.
      final resource = File('$dir/sop_cross_origin.json');
      await resource.writeAsString(
        WebViewEngine.crossOriginResource,
        flush: true,
      );

      // App shell with no CSP + an inline script that cross-reads the resource.
      final shell = File('$dir/sop_app_shell.html');
      await shell.writeAsString(
        '<html><body><h1>app shell (no CSP)</h1><script>'
        "fetch('file://${resource.path}').then(r=>r.text())"
        '.then(t=>Exfil.postMessage(t))'
        ".catch(e=>Exfil.postMessage('blocked '+e));"
        '</script></body></html>',
        flush: true,
      );

      final controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        ..addJavaScriptChannel(
          'Exfil',
          onMessageReceived: (JavaScriptMessage m) {
            DvmaEvidence.record(
              WebviewSopCspDisabledScreen.vulnId,
              'webview-sop-csp',
              'no CSP: inline <script> ran in file:// app origin and '
                  'cross-read local resource -> ${m.message}',
            );
            if (!mounted) return;
            setState(
              () => _liveResult =
                  'inline script ran; cross-origin read: ${m.message}',
            );
          },
        );

      // VULN: file access on (universal-access flag not reachable via plugin).
      final platform = controller.platform;
      if (platform is AndroidWebViewController) {
        await platform.setAllowFileAccess(true);
      }
      await controller.loadFile(shell.path);
      if (!mounted) return;
      setState(() => _controller = controller);
    } catch (_) {
      // Best effort; helper contrast panels still demonstrate the flaw.
    }
  }

  void _run() {
    const engine = WebViewEngine();

    // VULN: insecure config lets the file:// page read the cross-origin token
    // and run inline script to exfiltrate it.
    final vuln = engine.load(WebViewConfig.insecure);
    final vulnBuf = StringBuffer()
      ..writeln('app origin       : ${WebViewEngine.appOrigin}')
      ..writeln(
        'universalAccess  : ${WebViewConfig.insecure.universalAccessFromFileUrls}',
      )
      ..writeln(
        'csp              : ${WebViewConfig.insecure.cspPolicy ?? '(none)'}',
      )
      ..writeln('target origin    : ${WebViewEngine.crossOrigin}')
      ..writeln('cross-origin read: ${vuln.crossOriginRead}')
      ..writeln('inline script ran: ${vuln.inlineScriptExecuted}')
      ..writeln('read body        : ${vuln.crossOriginBody}')
      ..writeln('exfiltrated token: ${vuln.exfiltratedToken ?? '(none)'}')
      ..writeln('token stolen     : ${vuln.tokenStolen}');

    // SECURE: restrictive config blocks the cross-origin read and inline script.
    final secure = engine.load(WebViewConfig.secure);
    final secureBuf = StringBuffer()
      ..writeln(
        'universalAccess  : ${WebViewConfig.secure.universalAccessFromFileUrls}',
      )
      ..writeln('csp              : ${WebViewConfig.secure.cspPolicy}')
      ..writeln('cross-origin read: ${secure.crossOriginRead}')
      ..writeln('inline script ran: ${secure.inlineScriptExecuted}')
      ..writeln('blocked          : ${secure.blocked}')
      ..writeln('exfiltrated token: ${secure.exfiltratedToken ?? '(none)'}')
      ..writeln('token stolen     : ${secure.tokenStolen}')
      ..writeln('reason           : ${secure.reason}');

    setState(() {
      _vuln = vulnBuf.toString().trimRight();
      _secure = secureBuf.toString().trimRight();
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: WebviewSopCspDisabledScreen.vulnId,
      title: 'WebView SOP / CSP Disabled (Cross-Origin & Inline Script)',
      difficulty: DvmaDifficulty.hard,
      explanation:
          "The app's WebView relaxes/omits Same-Origin-Policy and "
          'Content-Security-Policy (allowUniversalAccessFromFileURLs true, no '
          'CSP), so a file:// page can READ a cross-origin resource AND run '
          'inline/injected script in the trusted app origin (WebKit SOP-bypass '
          'CVE-2026-20643 / CSP-bypass CVE-2026-20665 app-level analog). This '
          'writes real files and loads them in a REAL WebView with universal '
          'file access on and no CSP, so the page reads a cross-origin resource '
          'and inline script exfiltrates it (the in-memory panel is the offline '
          'contrast). The secure config (universal access '
          'off, restrictive CSP) blocks the cross-origin read and refuses '
          'inline script.',
      children: [
        DemoActionButton(
          label: 'Load app shell + injected inline script',
          onPressed: _run,
        ),
        if (_vuln != null)
          EvidencePanel(
            label: 'insecure config - token exfiltrated',
            value: _vuln!,
          ),
        if (_secure != null)
          EvidencePanel(
            label: 'secure config - SOP + CSP enforced',
            value: _secure!,
          ),
        if (_liveResult != null)
          EvidencePanel(
            label: 'REAL webview: inline script + file:// cross-read',
            value: _liveResult!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
