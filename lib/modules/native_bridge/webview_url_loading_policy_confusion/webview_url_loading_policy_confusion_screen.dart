import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'url_loading_policy.dart';

/// WebView URL-Loading Policy Confusion.
///
/// The navigation-policy handler trusts a raw, un-canonicalized URL, so
/// scheme/host confusion bypasses the allow/deny check and loads privileged
/// content.
class WebviewUrlLoadingPolicyConfusionScreen extends StatefulWidget {
  const WebviewUrlLoadingPolicyConfusionScreen({super.key});

  static const String vulnId = 'webview_url_loading_policy_confusion';

  @override
  State<WebviewUrlLoadingPolicyConfusionScreen> createState() =>
      _WebviewUrlLoadingPolicyConfusionScreenState();
}

class _WebviewUrlLoadingPolicyConfusionScreenState
    extends State<WebviewUrlLoadingPolicyConfusionScreen> {
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

  /// Boots a real WebView whose NavigationDelegate applies the NAIVE contains()
  /// allow-policy in onNavigationRequest. It then actually attempts to navigate
  /// to a crafted look-alike URL through that delegate and records whether the
  /// policy allowed it to load (NavigationDecision.navigate).
  Future<void> _bootRealWebView() async {
    try {
      const policy = UrlLoadingPolicy();
      const crafted = 'https://app.example.evil.com/account';
      final controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        ..setNavigationDelegate(
          NavigationDelegate(
            // VULN: the policy decision is made on the raw URL with a naive
            // contains() check; scheme/host confusion slips through.
            onNavigationRequest: (NavigationRequest req) {
              final decision = policy.shouldOverride(req.url);
              if (decision.loaded && decision.policyBypassed) {
                DvmaEvidence.record(
                  WebviewUrlLoadingPolicyConfusionScreen.vulnId,
                  'webview-url-policy',
                  'naive contains() navigation policy ALLOWED crafted URL '
                      '${req.url} (should be denied)',
                );
                if (mounted) {
                  setState(
                    () => _liveResult =
                        'delegate ALLOWED crafted URL:\n${req.url}',
                  );
                }
              }
              return decision.loaded
                  ? NavigationDecision.navigate
                  : NavigationDecision.prevent;
            },
          ),
        );
      // Attempt to load the crafted look-alike URL through the naive delegate.
      await controller.loadRequest(Uri.parse(crafted));
      if (!mounted) return;
      setState(() => _controller = controller);
    } catch (_) {
      // Best effort; helper contrast panels still demonstrate the flaw.
    }
  }

  String _renderVuln(List<UrlPolicyDecision> decisions) {
    final b = StringBuffer();
    b.writeln(
      'allowlist          : ${UrlLoadingPolicy.allowedScheme}://'
      '${UrlLoadingPolicy.allowedHost}',
    );
    for (final d in decisions) {
      b.writeln('');
      b.writeln('url                : ${d.url}');
      b.writeln('loaded             : ${d.loaded}');
      b.writeln('policy bypassed    : ${d.policyBypassed}');
    }
    return b.toString().trimRight();
  }

  String _renderSafe(List<UrlPolicyDecision> decisions) {
    final b = StringBuffer();
    b.writeln(
      'allowlist          : ${UrlLoadingPolicy.allowedScheme}://'
      '${UrlLoadingPolicy.allowedHost}',
    );
    for (final d in decisions) {
      b.writeln('');
      b.writeln('url                : ${d.url}');
      b.writeln('loaded             : ${d.loaded}');
      b.writeln(
        'deny reason        : ${d.denyReason ?? '(allowed: in scope)'}',
      );
    }
    return b.toString().trimRight();
  }

  void _run() {
    const policy = UrlLoadingPolicy();
    final urls = <String>[
      UrlLoadingPolicy.genuineUrl,
      ...UrlLoadingPolicy.craftedBypassUrls,
    ];

    // VULN: naive contains-check lets crafted scheme/host confusion through.
    final vuln = [for (final u in urls) policy.shouldOverride(u)];

    // SECURE: canonicalize + allowlist scheme AND exact host.
    final secure = [for (final u in urls) policy.shouldOverrideSafe(u)];

    setState(() {
      _vulnResult = _renderVuln(vuln);
      _secureResult = _renderSafe(secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: WebviewUrlLoadingPolicyConfusionScreen.vulnId,
      title: 'WebView URL-Loading Policy Confusion',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The WebView navigation-policy handler '
          '(shouldOverrideUrlLoading / decidePolicyForNavigationAction) makes '
          'its allow/deny trust decision on a RAW, un-canonicalized URL. A '
          'naive substring check against the intended host lets scheme/host '
          'confusion slip through: javascript: (script), file:// (local file '
          'read), content:// (privileged provider), a look-alike subdomain '
          '(app.example.evil.com), or the genuine host smuggled into a query '
          '(evil.example/?next=app.example). The bug is the POLICY '
          'IMPLEMENTATION, not loadUrl (MASTG-TEST-0332 class). This applies '
          'the naive policy in a REAL WebView navigation delegate and loads the '
          'crafted URL (the in-memory panel is the offline contrast). The '
          'secure path canonicalizes '
          'and parses the URL, then allowlists scheme (https only) AND the '
          'exact host, rejecting the crafted URLs while allowing the genuine '
          'one.',
      children: [
        DemoActionButton(
          label: 'Evaluate navigation policy for crafted URLs',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'naive policy: crafted URLs bypass and load',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'canonicalized policy: scheme + exact host allowlist',
            value: _secureResult!,
          ),
        if (_liveResult != null)
          EvidencePanel(
            label: 'REAL webview: naive delegate allowed crafted URL',
            value: _liveResult!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
