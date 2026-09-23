import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'accept_all_trust.dart';

/// Accept-All TrustManager.
///
/// Custom certificate callback accepts any certificate.
class AcceptAllTrustManagerScreen extends StatefulWidget {
  const AcceptAllTrustManagerScreen({super.key});

  static const String vulnId = 'accept_all_trust_manager';

  @override
  State<AcceptAllTrustManagerScreen> createState() =>
      _AcceptAllTrustManagerScreenState();
}

class _AcceptAllTrustManagerScreenState
    extends State<AcceptAllTrustManagerScreen> {
  String? _result;
  bool _sending = false;

  Future<void> _test() async {
    setState(() {
      _sending = true;
      _result = null;
    });

    // Exercise the actual insecure policy: make an HTTPS request with cert
    // validation disabled. Against a mitmproxy TLS intercept, the self-signed
    // cert is accepted and the flow is captured in plaintext.
    final base = context.read<AppConfig>().captureBase;
    // Force https even if the capture base is http, to exercise the TLS path.
    final httpsUrl = base.replaceFirst(RegExp('^http:'), 'https:');
    final summary = await AcceptAllTrust.fetchIgnoringCerts('$httpsUrl/secure');

    await DvmaEvidence.record(
      AcceptAllTrustManagerScreen.vulnId,
      'tls-mitm',
      summary,
    );

    if (!mounted) return;
    setState(() {
      _sending = false;
      _result = '$summary\nTLS validation bypassed; MITM cert accepted.';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: AcceptAllTrustManagerScreen.vulnId,
      title: 'Accept-All TrustManager',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The app installs an HttpClient.badCertificateCallback that returns '
          'true for every certificate/host - the Dart equivalent of an empty '
          'X509TrustManager. This makes an HTTPS request with validation '
          'off, so a Burp/mitmproxy self-signed cert is accepted and the "TLS" '
          'traffic is intercepted.',
      children: [
        EvidencePanel(
          label: 'installed callback',
          value: 'client.badCertificateCallback = (cert, host, port) => true;',
        ),
        DemoActionButton(
          label: _sending ? 'Connecting…' : 'Connect with validation off',
          onPressed: _sending ? () {} : () => _test(),
        ),
        if (_result != null)
          EvidencePanel(label: 'validation result', value: _result!),
      ],
    );
  }
}
