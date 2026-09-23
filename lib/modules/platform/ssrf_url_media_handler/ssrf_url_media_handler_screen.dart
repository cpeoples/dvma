import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'media_fetcher.dart';

/// SSRF via URL / Media Handler.
///
/// An attacker-controlled URL parameter passed into a fetch/media loader is not
/// restricted to an allowlist, so the app can be steered to internal/loopback
/// endpoints (WhatsApp iOS CVE-2026-23866 SSRF-via-URL-scheme class).
class SsrfUrlMediaHandlerScreen extends StatefulWidget {
  const SsrfUrlMediaHandlerScreen({super.key});

  static const String vulnId = 'ssrf_url_media_handler';

  @override
  State<SsrfUrlMediaHandlerScreen> createState() =>
      _SsrfUrlMediaHandlerScreenState();
}

class _SsrfUrlMediaHandlerScreenState extends State<SsrfUrlMediaHandlerScreen> {
  /// Attacker points the media loader at the cloud metadata endpoint. This is
  /// the default; the trainee can retarget it at any loopback/metadata URL.
  static const String _attackerUrl =
      'http://169.254.169.254/latest/meta-data/iam/security-credentials/';

  late final TextEditingController _url;
  String? _vulnResult;
  String? _secureResult;

  @override
  void initState() {
    super.initState();
    _url = TextEditingController(text: _attackerUrl);
  }

  @override
  void dispose() {
    _url.dispose();
    super.dispose();
  }

  String _render(FetchOutcome o) {
    final b = StringBuffer();
    b.writeln('requested url    : ${o.requestedUrl}');
    b.writeln('dispatched       : ${o.dispatched}');
    b.writeln('reached internal : ${o.reachedInternal}');
    if (o.status != null) {
      b.writeln('http status      : ${o.status}');
    }
    if (o.firstBytes != null) {
      b.writeln('first bytes      : ${o.firstBytes}');
    }
    if (o.blockReason != null) {
      b.writeln('block reason     : ${o.blockReason}');
    }
    return b.toString().trimRight();
  }

  Future<void> _run() async {
    final target = _url.text.trim();
    // VULN: media loader issues a real GET to the caller URL with no allowlist,
    // so a loopback/metadata target actually leaves the device (the SSRF).
    final vuln = await MediaFetcher.fetchReal(target);
    // SECURE: https + public-host allowlist blocks internal targets (no socket).
    final secure = MediaFetcher.fetchSafe(target);

    DvmaEvidence.record(
      SsrfUrlMediaHandlerScreen.vulnId,
      'ssrf',
      'GET $target\n${_render(vuln)}',
    );

    if (!mounted) return;
    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: SsrfUrlMediaHandlerScreen.vulnId,
      title: 'SSRF via URL / Media Handler',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'An attacker-controlled URL parameter is passed into a fetch/media '
          'loader with NO allowlist and no check that the destination is a '
          'public host. The app can be steered at internal/loopback/link-local '
          'endpoints - here the cloud metadata service (169.254.169.254) - '
          'issuing requests from inside the trust boundary (WhatsApp iOS '
          'CVE-2026-23866 SSRF-via-URL-scheme class). The vulnerable path opens '
          'a REAL socket to the caller URL, so the loopback/metadata request '
          'actually leaves the device - point it at your listener or the '
          'metadata IP and watch it in mitmproxy/tcpdump. The secure path only '
          'fetches https URLs on a public-host allowlist, refusing all internal '
          'targets without dispatching.',
      children: [
        TextField(
          controller: _url,
          decoration: const InputDecoration(labelText: 'Media URL to fetch'),
        ),
        DemoActionButton(label: 'Fetch attacker URL', onPressed: () => _run()),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'loader fetched caller url (no allowlist)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'https + public-host allowlist',
            value: _secureResult!,
          ),
      ],
    );
  }
}
