import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'debuggable_webview.dart';

/// WebView Remote Debugging Enabled.
///
/// A release build leaves setWebContentsDebuggingEnabled(true) on, so a remote
/// DevTools inspector attaches and dumps web-context secrets.
class WebviewRemoteDebuggingEnabledScreen extends StatefulWidget {
  const WebviewRemoteDebuggingEnabledScreen({super.key});

  static const String vulnId = 'webview_remote_debugging_enabled';

  @override
  State<WebviewRemoteDebuggingEnabledScreen> createState() =>
      _WebviewRemoteDebuggingEnabledScreenState();
}

class _WebviewRemoteDebuggingEnabledScreenState
    extends State<WebviewRemoteDebuggingEnabledScreen> {
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

  /// Boots a real WebView with WebContents debugging turned ON (the release
  /// misconfiguration) and loads a page whose JS context holds the session
  /// token, so a remote chrome://inspect DevTools session can attach and dump
  /// it.
  Future<void> _bootRealWebView() async {
    try {
      // VULN: setWebContentsDebuggingEnabled(true), process-wide, exposes the
      // WebView over the Chrome DevTools Protocol for chrome://inspect.
      await AndroidWebViewController.enableDebugging(true);

      final controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted);
      // Put the session token into the live web context (window.__session) so a
      // DevTools console eval / Runtime.evaluate reads it straight out.
      await controller.loadHtmlString(
        '<html><body><h1>account</h1><script>'
        'window.__session=${_jsString(DebuggableWebView.sessionToken)};'
        'document.cookie=${_jsString(DebuggableWebView.sessionToken)};'
        '</script></body></html>',
      );
      // Confirm the secret is present in the live JS context an inspector reads.
      final leaked = await controller.runJavaScriptReturningResult(
        'window.__session',
      );
      DvmaEvidence.record(
        WebviewRemoteDebuggingEnabledScreen.vulnId,
        'webview-remote-debug',
        'setWebContentsDebuggingEnabled(true) in release: chrome://inspect can '
            'attach; live web-context secret readable via DevTools -> $leaked',
      );
      if (!mounted) return;
      setState(() {
        _controller = controller;
        _liveResult =
            'debugging ENABLED (chrome://inspect attachable)\n'
            'window.__session readable via DevTools = $leaked';
      });
    } catch (_) {
      // Best effort; helper contrast panels still demonstrate the flaw.
    }
  }

  /// Quote a Dart string as a JS string literal.
  static String _jsString(String s) =>
      '"${s.replaceAll(r'\', r'\\').replaceAll('"', r'\"')}"';

  String _render(InspectorAttachResult r) {
    final b = StringBuffer();
    b.writeln('isReleaseBuild     : ${r.isReleaseBuild}');
    b.writeln('debuggingEnabled   : ${r.debuggingEnabled}');
    b.writeln('inspector attached : ${r.inspectorAttached}');
    b.writeln('secrets exposed    : ${r.secretsExposed}');
    b.writeln('exposed token      : ${r.exposedToken ?? '(none)'}');
    b.writeln('release leaked     : ${r.releaseSecretsLeaked}');
    if (r.denyReason != null) {
      b.writeln('reason             : ${r.denyReason}');
    }
    return b.toString().trimRight();
  }

  void _run() {
    // VULN: debugging left on in a release build -> inspector dumps secrets.
    final vulnWv = DebuggableWebView(
      debuggingEnabled: true,
      isReleaseBuild: true,
    );
    final vuln = vulnWv.attachInspector();

    // SECURE: release build forces debugging off -> inspector cannot attach.
    final secureWv = DebuggableWebView(
      debuggingEnabled: true,
      isReleaseBuild: true,
    );
    final secure = secureWv.configureSafe(isReleaseBuild: true);

    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: WebviewRemoteDebuggingEnabledScreen.vulnId,
      title: 'WebView Remote Debugging Enabled',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The app leaves WebView.setWebContentsDebuggingEnabled(true) on in a '
          'RELEASE build. That exposes the WebView over the Chrome DevTools '
          'Protocol, so anyone with adb / chrome://inspect access attaches '
          'DevTools to the app web context, inspects the live DOM/JS, and '
          'evaluates script - reading the session cookie/token and auth '
          'material in the page (Android WebView MASTG-TEST-0227 class). This '
          'boots a REAL WebView with debugging enabled and reads the live JS '
          'context back; the in-memory panel is the offline contrast. The '
          'secure path forces debugging OFF in release builds so the '
          'inspector fails closed, while still allowing DevTools in debug '
          'builds for local development.',
      children: [
        DemoActionButton(
          label: 'Attach remote DevTools inspector',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'debugging on in release: inspector dumped secrets',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'release build: debugging disabled, inspector refused',
            value: _secureResult!,
          ),
        if (_liveResult != null)
          EvidencePanel(
            label: 'REAL webview: setWebContentsDebuggingEnabled(true)',
            value: _liveResult!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
