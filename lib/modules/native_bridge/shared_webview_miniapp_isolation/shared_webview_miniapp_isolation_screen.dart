import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'shared_webview_host.dart';

/// Shared WebView Mini-App Isolation Failure (Cross-Tenant Cookies).
///
/// A super-app hosts multiple mini-programs in one shared WebView with a single
/// shared cookie jar, so mini-app A reads mini-app B's cookies. The secure path
/// partitions storage per mini-app origin so A cannot see B's cookie.
class SharedWebviewMiniappIsolationScreen extends StatefulWidget {
  const SharedWebviewMiniappIsolationScreen({super.key});

  static const String vulnId = 'shared_webview_miniapp_isolation';

  @override
  State<SharedWebviewMiniappIsolationScreen> createState() =>
      _SharedWebviewMiniappIsolationScreenState();
}

class _SharedWebviewMiniappIsolationScreenState
    extends State<SharedWebviewMiniappIsolationScreen> {
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

  /// Boots ONE shared real WebView (a single controller = single web storage
  /// partition, as a super-app hosting mini-programs in one WebView). Mini-app
  /// B writes its session cookie into localStorage; then mini-app A, running in
  /// the SAME WebView, reads B's cookie straight out of the shared jar.
  Future<void> _bootRealWebView() async {
    try {
      final controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        ..addJavaScriptChannel(
          'Leak',
          onMessageReceived: (JavaScriptMessage m) {
            DvmaEvidence.record(
              SharedWebviewMiniappIsolationScreen.vulnId,
              'webview-shared-storage',
              'mini-app A read mini-app B cookie from the shared WebView '
                  'localStorage (no per-origin partition) -> ${m.message}',
            );
            if (!mounted) return;
            setState(
              () => _liveResult = 'mini-app A read B\'s cookie: ${m.message}',
            );
          },
        )
        ..setNavigationDelegate(
          NavigationDelegate(
            onPageFinished: (_) {
              // Mini-app A runs in the SAME WebView after B's page committed
              // its cookie into shared localStorage, and reads it back.
              _controller?.runJavaScript(
                'Leak.postMessage(localStorage.getItem('
                '${_jsString(SharedWebViewHost.cookieName)}))',
              );
            },
          ),
        );

      // Mini-app B stores its cookie into the single shared web storage.
      await controller.loadHtmlString(
        '<html><body><h1>mini-app B</h1><script>'
        'localStorage.setItem(${_jsString(SharedWebViewHost.cookieName)},'
        '${_jsString(SharedWebViewHost.miniBCookie)});'
        '</script></body></html>',
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

  void _run() {
    // VULN: B writes its cookie into the single shared jar; A reads it back.
    final vulnHost = SharedWebViewHost();
    vulnHost.storeCookie(
      origin: SharedWebViewHost.miniAppB,
      name: SharedWebViewHost.cookieName,
      value: SharedWebViewHost.miniBCookie,
      partitioned: false,
    );
    final vulnRead = vulnHost.readCookie(
      readerOrigin: SharedWebViewHost.miniAppA,
      name: SharedWebViewHost.cookieName,
    );
    final vulnBuf = StringBuffer()
      ..writeln('host           : one shared WebView, one cookie jar')
      ..writeln('cookie owner   : ${SharedWebViewHost.miniAppB}')
      ..writeln('reader         : ${SharedWebViewHost.miniAppA}')
      ..writeln('cookie name    : ${SharedWebViewHost.cookieName}')
      ..writeln('read value     : ${vulnRead.value ?? '(none)'}')
      ..writeln(
        'cross-tenant leak: '
        '${vulnRead.crossTenantLeak(SharedWebViewHost.miniAppA, SharedWebViewHost.miniAppB)}',
      )
      ..writeln('reason         : ${vulnRead.reason}');

    // SECURE: B's cookie goes into B's partition; A reads its own partition and
    // gets nothing.
    final safeHost = SharedWebViewHost();
    safeHost.storeCookie(
      origin: SharedWebViewHost.miniAppB,
      name: SharedWebViewHost.cookieName,
      value: SharedWebViewHost.miniBCookie,
      partitioned: true,
    );
    final safeRead = safeHost.readCookieSafe(
      readerOrigin: SharedWebViewHost.miniAppA,
      name: SharedWebViewHost.cookieName,
    );
    // B can still read its own cookie.
    final safeOwn = safeHost.readCookieSafe(
      readerOrigin: SharedWebViewHost.miniAppB,
      name: SharedWebViewHost.cookieName,
    );
    final secureBuf = StringBuffer()
      ..writeln('host           : per-origin partitioned storage')
      ..writeln('--- mini-app A reads B\'s cookie ---')
      ..writeln('read value     : ${safeRead.value ?? '(none)'}')
      ..writeln('blocked        : ${safeRead.blocked}')
      ..writeln(
        'cross-tenant leak: '
        '${safeRead.crossTenantLeak(SharedWebViewHost.miniAppA, SharedWebViewHost.miniAppB)}',
      )
      ..writeln('reason         : ${safeRead.reason}')
      ..writeln('--- mini-app B reads its own cookie ---')
      ..writeln('read value     : ${safeOwn.value ?? '(none)'}')
      ..writeln('granted        : ${safeOwn.granted}');

    setState(() {
      _vuln = vulnBuf.toString().trimRight();
      _secure = secureBuf.toString().trimRight();
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: SharedWebviewMiniappIsolationScreen.vulnId,
      title: 'Shared WebView Mini-App Isolation Failure (Cross-Tenant Cookies)',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A super-app hosts multiple mini-programs in ONE shared WebView '
          'instance with a SINGLE shared cookie jar / localStorage keyed '
          "loosely, so mini-app A reads mini-app B's cookies and storage - a "
          'cross-tenant isolation failure enabling data exfiltration between '
          'mini-apps (WeChat / Alipay / TikTok / Baidu cross-mini-program '
          'cookie-sharing research). This loads two mini-apps in one REAL '
          'shared WebView so mini-app A reads B\'s cookie/storage from the '
          'shared jar (the in-memory panel is the offline contrast). The '
          'secure path partitions '
          'storage per mini-app origin, so A cannot see B\'s cookie while B '
          'still reads its own.',
      children: [
        DemoActionButton(
          label: 'Mini-app A reads mini-app B\'s cookie',
          onPressed: _run,
        ),
        if (_vuln != null)
          EvidencePanel(
            label: 'shared jar - cross-tenant cookie leaked',
            value: _vuln!,
          ),
        if (_secure != null)
          EvidencePanel(
            label: 'partitioned - cross-tenant read blocked',
            value: _secure!,
          ),
        if (_liveResult != null)
          EvidencePanel(
            label: 'REAL shared webview: A read B\'s cookie',
            value: _liveResult!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
