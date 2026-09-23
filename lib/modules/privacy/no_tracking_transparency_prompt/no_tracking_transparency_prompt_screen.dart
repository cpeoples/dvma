import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show MissingPluginException;
import 'package:http/http.dart' as http;
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/native/att_bridge.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// No Tracking Transparency Prompt.
///
/// Cross-app tracking begins with no ATT-equivalent prompt.
class NoTrackingTransparencyPromptScreen extends StatefulWidget {
  const NoTrackingTransparencyPromptScreen({super.key});

  static const String vulnId = 'no_tracking_transparency_prompt';

  @override
  State<NoTrackingTransparencyPromptScreen> createState() =>
      _NoTrackingTransparencyPromptScreenState();
}

class _NoTrackingTransparencyPromptScreenState
    extends State<NoTrackingTransparencyPromptScreen> {
  // VULN: cross-app tracking starts immediately, reading the advertising
  // identifier (IDFA/GAID), with no App Tracking Transparency-style prompt.
  static const bool attPromptShown = false;
  static const String _adId = 'a1b2c3d4-e5f6-7890-aaaa-bbbbccccdddd';
  String? _tracking;
  bool _sending = false;

  Future<void> _start() async {
    setState(() => _sending = true);
    final base = context.read<AppConfig>().captureBase;

    // On iOS, read the real ATT authorization status + IDFA to prove the app
    // tracks with no prompt shown (status .notDetermined) rather than assert it.
    final attState = await AttBridge.trackingState();

    // VULN: persist the harvested advertising identifier locally (real prefs
    // write), a durable tracking id kept without any consent.
    var persistedPath = '(prefs unavailable on this host)';
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('advertising_id', _adId);
      await prefs.setBool('att_prompt_shown', attPromptShown);
      persistedPath =
          '${PlatformLingo.current().keyValueBackingFile} key=advertising_id';
    } on MissingPluginException {
      // Test-safe: the logcat/http mirror below still proves the effect.
    }

    // VULN: exfiltrate the advertising id to the tracking endpoint over the
    // wire, with no ATT prompt / opt-out honored. A capture listener/mitmproxy
    // sees the id leave the device.
    var wire = '';
    final uri = Uri.parse('$base/track');
    final body =
        '{"ad_id":"$_adId","att_prompt_shown":$attPromptShown,'
        '"purpose":"cross-app-profiling"}';
    try {
      final resp = await http
          .post(
            uri,
            headers: const {'Content-Type': 'application/json'},
            body: body,
          )
          .timeout(const Duration(seconds: 6));
      wire =
          'POST ${uri.path} -> HTTP ${resp.statusCode} '
          '(${resp.bodyBytes.length} bytes)';
    } catch (e) {
      final s = e.toString();
      wire =
          'POST ${uri.path} -> no response (${s.length <= 80 ? s : '${s.substring(0, 77)}...'})';
    }

    // Mirror the leaked tracking id to the pullable evidence sink.
    await DvmaEvidence.record(
      NoTrackingTransparencyPromptScreen.vulnId,
      'tracking-id',
      'advertising id harvested WITHOUT consent = $_adId\n'
          'att prompt shown = $attPromptShown\n'
          '${attState != null ? 'real iOS ATT state: $attState\n' : ''}'
          'persisted: $persistedPath\n'
          'exfiltrated: POST $uri\n$body\n$wire',
    );

    if (!mounted) return;
    setState(() {
      _sending = false;
      _tracking =
          'reading IDFA/GAID = $_adId\n'
          '${attState != null ? 'real iOS ATT state: $attState\n' : ''}'
          'persisted to prefs: $persistedPath\n'
          'linking to 3 ad networks for cross-app profiling\n'
          'ATT prompt shown = $attPromptShown\n'
          'exfiltrated -> $wire';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: NoTrackingTransparencyPromptScreen.vulnId,
      title: 'No Tracking Transparency Prompt',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'The app begins cross-app tracking - reading the advertising ID, '
          'persisting it, and POSTing it to a tracking endpoint - without ever '
          'showing an App Tracking Transparency (or equivalent) prompt or '
          'honoring an opt-out. Point the capture base at your listener and the '
          'advertising id appears on the wire.',
      children: [
        DemoActionButton(
          label: _sending ? 'Starting…' : 'Launch app (starts tracking)',
          onPressed: _sending ? () {} : () => _start(),
        ),
        if (_tracking != null)
          EvidencePanel(
            label: 'tracking started (no prompt)',
            value: _tracking!,
          ),
      ],
    );
  }
}
