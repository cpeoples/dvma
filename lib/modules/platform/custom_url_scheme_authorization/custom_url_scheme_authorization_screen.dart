import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'custom_scheme_handler.dart';

/// Custom URL Scheme Authorization (arbitrary URL load).
///
/// A custom URL-scheme handler loads a caller-supplied URL without checking the
/// caller or an allowlist, so any co-resident app can make DVMA display an
/// attacker site (Rakuten CVE-2024-41918 / @cosme CVE-2024-45203 / Skylark
/// CVE-2024-54014 / Groww CVE-2026-12065 class).
class CustomUrlSchemeAuthorizationScreen extends StatefulWidget {
  const CustomUrlSchemeAuthorizationScreen({super.key});

  static const String vulnId = 'custom_url_scheme_authorization';

  @override
  State<CustomUrlSchemeAuthorizationScreen> createState() =>
      _CustomUrlSchemeAuthorizationScreenState();
}

class _CustomUrlSchemeAuthorizationScreenState
    extends State<CustomUrlSchemeAuthorizationScreen> {
  /// A malicious co-resident app fires this deep link.
  static const String _attackerDeepLink =
      'dvma://open?url=https://evil.example/phish?session=steal';

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

  String _render(SchemeHandleResult r) {
    final b = StringBuffer();
    b.writeln('displayed url     : ${r.displayedUrl ?? '(none)'}');
    b.writeln('blocked           : ${r.blocked}');
    if (r.blockReason != null) {
      b.writeln('block reason      : ${r.blockReason}');
    }
    b.writeln('displayed untrusted : ${r.displayedUntrusted}');
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // VULN: handler loads the caller-supplied url with no checks.
    final vuln = CustomSchemeHandler.handle(_attackerDeepLink);
    // SECURE: scheme + trusted-host allowlist.
    final secure = CustomSchemeHandler.handleSafe(_attackerDeepLink);
    // real artifact: record the unauthenticated deep link that triggered the
    // privileged, caller-controlled URL load.
    await DvmaEvidence.record(
      CustomUrlSchemeAuthorizationScreen.vulnId,
      'deeplink',
      'unauthenticated deep link=$_attackerDeepLink loaded caller-controlled '
          'url=${vuln.displayedUrl} (displayedUntrusted=${vuln.displayedUntrusted})',
    );
    if (!mounted) return;
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // On Android, hand the caller-supplied URL straight to the real in-app
    // WebView (no caller/allowlist check), the exact CVE-class sink.
    final controller = _controller;
    final target = vuln.displayedUrl;
    if (controller != null && target != null) {
      try {
        await controller.loadRequest(Uri.parse(target));
        if (!mounted) return;
        setState(
          () => _nativeResult =
              'real in-app WebView loaded caller-supplied url=$target with no '
              'caller/allowlist check (rendered inside DVMA trusted chrome)',
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
      vulnId: CustomUrlSchemeAuthorizationScreen.vulnId,
      title: 'Custom URL Scheme Authorization (arbitrary URL load)',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The app registers a custom URL scheme (dvma://open?url=...) whose '
          'handler loads the caller-supplied "url" parameter WITHOUT checking '
          'the caller or an allowlist. Any co-resident app can fire the scheme '
          'and make DVMA render an attacker-controlled site inside its trusted '
          'chrome (Rakuten CVE-2024-41918 / @cosme CVE-2024-45203 / Skylark '
          'CVE-2024-54014 / Groww CVE-2026-12065 class). On Android the '
          'caller-supplied URL is loaded into a REAL in-app WebView '
          '(loadRequest) inside DVMA\'s trusted chrome. The secure path only '
          'displays https URLs on a trusted-host allowlist and refuses '
          'everything else.',
      children: [
        DemoActionButton(label: 'Fire dvma:// deep link', onPressed: _run),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'handler loaded caller url (no checks)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'scheme + host allowlist enforced',
            value: _secureResult!,
          ),
        if (_nativeResult != null)
          EvidencePanel(
            label: 'real WebView loaded the caller-supplied url',
            value: _nativeResult!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
