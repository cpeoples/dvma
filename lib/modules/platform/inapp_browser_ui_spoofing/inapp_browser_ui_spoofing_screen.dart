import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'inapp_browser_model.dart';

/// In-App Browser UI / Address-Bar Spoofing.
///
/// An in-app WebView browser derives the displayed origin/address-bar from
/// attacker-controllable content instead of the real committed URL, enabling
/// website spoofing / UI misrepresentation (Firefox Focus CVE-2025-10290 /
/// LINE CVE-2024-5739 trust class).
class InappBrowserUiSpoofingScreen extends StatefulWidget {
  const InappBrowserUiSpoofingScreen({super.key});

  static const String vulnId = 'inapp_browser_ui_spoofing';

  @override
  State<InappBrowserUiSpoofingScreen> createState() =>
      _InappBrowserUiSpoofingScreenState();
}

class _InappBrowserUiSpoofingScreenState
    extends State<InappBrowserUiSpoofingScreen> {
  // The WebView actually commits to the attacker's site, but the page claims a
  // trusted bank origin via its title/pushState.
  static const BrowserPage _page = BrowserPage(
    committedUrl: 'https://evil.example/login',
    claimedOrigin: 'https://bank.example',
  );

  String? _vulnResult;
  String? _secureResult;
  String? _nativeResult;

  WebViewController? _controller;

  @override
  void initState() {
    super.initState();
    if (supportsRealWebView) {
      _controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted);
    }
  }

  Future<void> _run() async {
    final vuln = InAppBrowserModel.displayedAddressBar(_page);
    final secure = InAppBrowserModel.displayedAddressBarSafe(_page);
    // real artifact: record the spoofed address bar (shown trusted origin) vs
    // the real committed URL the WebView actually loaded.
    await DvmaEvidence.record(
      InappBrowserUiSpoofingScreen.vulnId,
      'address-bar-spoof',
      'address bar SHOWED=${vuln.shown} but real committed origin='
          '${vuln.actual} (spoofed=${vuln.spoofed})',
    );
    if (!mounted) return;
    setState(() {
      _vulnResult =
          'address bar shows: ${vuln.shown}\n'
          'real committed origin: ${vuln.actual}\n'
          'spoofed: ${vuln.spoofed}';
      _secureResult =
          'address bar shows: ${secure.shown}\n'
          'real committed origin: ${secure.actual}\n'
          'spoofed: ${secure.spoofed}';
    });

    // On Android, load a real page (committed to the attacker origin) that sets
    // document.title to a trusted-looking origin, then drive the address bar
    // from the page-controlled title via runJavaScriptReturningResult, the
    // real spoofing sink.
    final controller = _controller;
    if (controller != null) {
      try {
        await controller.loadHtmlString(
          '<html><head><title>${_page.claimedOrigin}</title></head>'
          '<body>attacker page committed at ${_page.committedUrl}</body></html>',
        );
        final title = await controller.runJavaScriptReturningResult(
          'document.title',
        );
        final shownFromTitle = title.toString().replaceAll('"', '');
        if (!mounted) return;
        setState(
          () => _nativeResult =
              'real WebView committed a page and read document.title='
              '"$shownFromTitle"; address bar driven from that page-controlled '
              'title shows "$shownFromTitle" while real committed origin is '
              '${_page.committedUrl}',
        );
      } catch (e) {
        if (!mounted) return;
        setState(() => _nativeResult = 'native error: $e');
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: InappBrowserUiSpoofingScreen.vulnId,
      title: 'In-App Browser UI / Address-Bar Spoofing',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The in-app WebView browser builds the origin shown in its address '
          'bar from ATTACKER-CONTROLLABLE page content (document.title, a '
          'pushState path, or a data:/about: trick) instead of the real '
          'committed URL. So the chrome shows a trusted https://bank.example '
          'while the page actually loaded is the attacker\'s '
          'https://evil.example - the user trusts a lie and enters credentials '
          '(the Firefox Focus CVE-2025-10290 / LINE CVE-2024-5739 trust class). '
          'On Android this drives a REAL in-app WebView: the loaded page sets '
          'document.title, and the address bar is driven from that '
          'page-controlled title (read via runJavaScriptReturningResult) rather '
          'than the true committed origin. The secure version always derives the '
          'address bar from the true committed origin, ignoring page claims.',
      children: [
        DemoActionButton(
          label: 'Load page (attacker sets fake title/origin)',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'content-derived address bar (shows spoofed origin)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'committed-URL address bar (shows true origin)',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real WebView: address bar driven from page document.title',
            value: _nativeResult!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
