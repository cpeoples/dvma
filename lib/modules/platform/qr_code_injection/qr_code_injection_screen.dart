import 'dart:async';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:webview_flutter/webview_flutter.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import '../../../core/widgets/qr_scan_button.dart';
import '../deeplink_url_scheme_hijack/deep_link_handler.dart';
import 'qr_action_handler.dart';

/// QR Code Injection.
///
/// Scanner trusts scanned content and acts on it without validation.
class QrCodeInjectionScreen extends StatefulWidget {
  const QrCodeInjectionScreen({super.key});

  static const String vulnId = 'qr_code_injection';

  @override
  State<QrCodeInjectionScreen> createState() => _QrCodeInjectionScreenState();
}

class _QrCodeInjectionScreenState extends State<QrCodeInjectionScreen> {
  final _scanned = TextEditingController(text: QrActionHandler.hostileSample);
  String? _action;
  String? _sinkResult;

  WebViewController? _controller;

  @override
  void initState() {
    super.initState();
    if (supportsRealWebView) {
      _controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        ..loadRequest(Uri.parse('https://app.dvma.example/account'));
    }
  }

  // The paste-decoded field below is the tested/CI path. An optional live
  // camera scan (mobile only) writes the decoded value into the same field and
  // runs the identical vulnerable path.
  Future<void> _scan() async {
    final decoded = _scanned.text;
    final action = QrActionHandler.handle(decoded);
    // real artifact: record the untrusted scanned payload and the privileged
    // action the scanner took on it with no validation/confirmation.
    await DvmaEvidence.record(
      QrCodeInjectionScreen.vulnId,
      'qr-action',
      'scanned untrusted QR content=$decoded -> action taken=$action',
    );
    if (!mounted) return;
    setState(() => _action = action);

    // Route the decoded payload to a real sink with no validation, mirroring
    // qr_url_no_validation: dvma:// -> real deep-link router; javascript: ->
    // real in-app WebView; http(s) -> real http.get follow.
    final sink = await _routeToRealSink(decoded);
    if (!mounted) return;
    setState(() => _sinkResult = sink);
  }

  Future<String> _routeToRealSink(String decoded) async {
    final value = decoded.trim();
    if (value.startsWith('dvma://')) {
      // Real deep-link router honors the attacker-chosen params (no origin
      // check), the same routed sink qr_url_no_validation exercises.
      final routed = DeepLinkHandler.handle(value);
      return 'dvma:// routed through real deep-link handler: '
          '${routed['action'] ?? routed}';
    }
    if (value.startsWith('javascript:')) {
      final controller = _controller;
      if (controller == null) {
        return 'javascript: sink unavailable on this host';
      }
      try {
        await controller.runJavaScript(value.substring('javascript:'.length));
        return 'ran javascript: payload in real in-app WebView (trusted origin)';
      } catch (e) {
        return 'native error: $e';
      }
    }
    final parsed = Uri.tryParse(value);
    if (parsed != null &&
        (parsed.scheme == 'http' || parsed.scheme == 'https')) {
      try {
        final resp = await http.get(parsed).timeout(const Duration(seconds: 5));
        return 'followed http.get($value) -> status=${resp.statusCode} '
            'bytes=${resp.bodyBytes.length}';
      } catch (e) {
        return 'http.get attempted, error=$e';
      }
    }
    return 'processed verbatim (no scheme matched a network sink)';
  }

  void _onScanned(String decoded) {
    _scanned.text = decoded;
    unawaited(_scan());
  }

  @override
  void dispose() {
    _scanned.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: QrCodeInjectionScreen.vulnId,
      title: 'QR Code Injection',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The QR scanner trusts whatever it decodes and immediately acts on '
          'it - following dvma:// app commands, javascript:/file: URIs, and '
          'links - with no validation or confirmation. A malicious QR triggers '
          'privileged actions. Enter the decoded value below (stands in for the '
          'camera scan).',
      children: [
        TextField(
          controller: _scanned,
          decoration: const InputDecoration(labelText: 'decoded QR content'),
        ),
        DemoActionButton(label: 'Process scan', onPressed: _scan),
        QrScanButton(onScanned: _onScanned),
        if (_action != null)
          EvidencePanel(
            label: 'action taken (no confirmation)',
            value: _action!,
          ),
        if (_sinkResult != null)
          EvidencePanel(
            label: 'routed to real sink (deep-link / WebView / http)',
            value: _sinkResult!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
