import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:provider/provider.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'analytics_events.dart';

/// PII in Analytics Events.
///
/// Raw PII (email, precise location) sent unfiltered in analytics events.
class PiiInAnalyticsEventsScreen extends StatefulWidget {
  const PiiInAnalyticsEventsScreen({super.key});

  static const String vulnId = 'pii_in_analytics_events';

  @override
  State<PiiInAnalyticsEventsScreen> createState() =>
      _PiiInAnalyticsEventsScreenState();
}

class _PiiInAnalyticsEventsScreenState
    extends State<PiiInAnalyticsEventsScreen> {
  final _analytics = AnalyticsEvents();
  String? _event;

  Future<void> _track() async {
    final e = _analytics.track();
    final json = const JsonEncoder.withIndent('  ').convert(e);

    // VULN: real POST of the raw-PII analytics event to the capture listener.
    // The email, full name, precise lat/lng and device id cross the wire
    // unfiltered, readable verbatim in mitmproxy/tcpdump.
    final base = context.read<AppConfig>().captureBase;
    final url = '$base/analytics';
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
      // The packet still left the device even if the listener didn't reply.
      outcome = 'POST $url -> no response ($err)';
    }

    // Mirror the exfil so the harness can pull it (fire-and-forget).
    DvmaEvidence.record(
      PiiInAnalyticsEventsScreen.vulnId,
      'pii-exfil',
      'POST $url\n$json',
    );

    if (!mounted) return;
    setState(() => _event = '$json\n\n-> $outcome');
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: PiiInAnalyticsEventsScreen.vulnId,
      title: 'PII in Analytics Events',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'Analytics events attach raw PII - email, full name, precise '
          'location, device id - and send it to ${AnalyticsEvents.endpoint} '
          'unfiltered. PII should be stripped, hashed, or aggregated before '
          'leaving the device. A pentester reads it in mitmproxy.',
      children: [
        DemoActionButton(
          label: 'Track purchase event',
          onPressed: () => _track(),
        ),
        if (_event != null)
          EvidencePanel(label: 'event sent (raw PII)', value: _event!),
      ],
    );
  }
}
