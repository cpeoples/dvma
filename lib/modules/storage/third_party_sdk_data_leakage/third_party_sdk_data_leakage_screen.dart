import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'analytics_sdk.dart';

/// Third-Party SDK Data Leakage.
///
/// A stand-in analytics SDK phones home more data than its stated purpose.
class ThirdPartySdkDataLeakageScreen extends StatefulWidget {
  const ThirdPartySdkDataLeakageScreen({super.key});

  static const String vulnId = 'third_party_sdk_data_leakage';

  @override
  State<ThirdPartySdkDataLeakageScreen> createState() =>
      _ThirdPartySdkDataLeakageScreenState();
}

class _ThirdPartySdkDataLeakageScreenState
    extends State<ThirdPartySdkDataLeakageScreen> {
  final _sdk = AnalyticsSdk();
  String? _payload;

  Future<void> _track() async {
    final payload = _sdk.track('CheckoutScreen');
    final json = const JsonEncoder.withIndent('  ').convert(payload);
    // real side effect: actually fire the over-collected event to the SDK
    // endpoint over the wire (a pentester sees this request in mitmproxy).
    var wire = 'POST ${AnalyticsSdk.endpoint}';
    try {
      final resp = await http
          .post(
            Uri.parse(AnalyticsSdk.endpoint),
            headers: const {'content-type': 'application/json'},
            body: jsonEncode(payload),
          )
          .timeout(const Duration(seconds: 5));
      wire += ' -> status=${resp.statusCode}';
    } catch (e) {
      wire += ' -> attempted, error=$e';
    }
    // real artifact: the exfiltrated (over-collected) payload + the request.
    await DvmaEvidence.record(
      ThirdPartySdkDataLeakageScreen.vulnId,
      'sdk-exfil',
      '$wire :: over-collected payload=${jsonEncode(payload)}',
    );
    if (!mounted) return;
    setState(() => _payload = json);
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ThirdPartySdkDataLeakageScreen.vulnId,
      title: 'Third-Party SDK Data Leakage',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'A bundled analytics SDK claims to just count screen views, but every '
          'event it sends to ${AnalyticsSdk.endpoint} is enriched with email, '
          'ad/device IDs, precise location, installed apps, and contact counts '
          '- none of which the feature needs. A pentester sees this in '
          'mitmproxy.',
      children: [
        DemoActionButton(label: 'Track screen view', onPressed: _track),
        if (_payload != null)
          EvidencePanel(
            label: 'payload sent to ${AnalyticsSdk.endpoint}',
            value: _payload!,
          ),
      ],
    );
  }
}
