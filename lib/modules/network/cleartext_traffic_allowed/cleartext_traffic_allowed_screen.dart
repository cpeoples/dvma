import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:provider/provider.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';

/// Cleartext Traffic Allowed.
///
/// App sends requests over plain HTTP; cleartext permitted in manifest/plist.
class CleartextTrafficAllowedScreen extends StatefulWidget {
  const CleartextTrafficAllowedScreen({super.key});

  static const String vulnId = 'cleartext_traffic_allowed';

  @override
  State<CleartextTrafficAllowedScreen> createState() =>
      _CleartextTrafficAllowedScreenState();
}

class _CleartextTrafficAllowedScreenState
    extends State<CleartextTrafficAllowedScreen> {
  late final TextEditingController _url;
  String? _wire;
  bool _sending = false;

  @override
  void initState() {
    super.initState();
    // Default target is the local capture listener (mitmproxy) so real packets
    // hit the trainee's own host over cleartext http://.
    final base = context.read<AppConfig>().captureBase;
    _url = TextEditingController(text: '$base/login');
  }

  @override
  void dispose() {
    _url.dispose();
    super.dispose();
  }

  Future<void> _send() async {
    setState(() {
      _sending = true;
      _wire = null;
    });

    // VULN: real POST built against an http:// URL. android:usesCleartextTraffic
    // is true / NSAllowsArbitraryLoads is set, so the credentials below cross
    // the wire in the clear, readable by anyone on the path or by mitmproxy.
    final uri = Uri.parse(_url.text.trim());
    const body = '{"user":"alice","password":"Sup3rSecret!"}';
    final request =
        'POST ${uri.path} HTTP/1.1\n'
        'Host: ${uri.host}\n'
        'Content-Type: application/json\n\n'
        '$body';

    var outcome = '';
    try {
      final resp = await http
          .post(
            uri,
            headers: const {'Content-Type': 'application/json'},
            body: body,
          )
          .timeout(const Duration(seconds: 6));
      outcome =
          'sent over ${uri.scheme} -> HTTP ${resp.statusCode} '
          '(${resp.bodyBytes.length} bytes)';
    } catch (e) {
      // A connection error still proves the cleartext packet left the device
      // (the capture listener/mitmproxy sees it even if it doesn't reply).
      outcome = 'sent over ${uri.scheme} -> no response (${_short(e)})';
    }

    await DvmaEvidence.record(
      CleartextTrafficAllowedScreen.vulnId,
      'http-request',
      '$request\n\n$outcome',
    );

    if (!mounted) return;
    setState(() {
      _sending = false;
      _wire =
          '$request\n\n-> scheme=${uri.scheme} '
          '${uri.scheme == 'http' ? '(CLEARTEXT - sniffable)' : '(encrypted)'}'
          '\n-> $outcome';
    });
  }

  static String _short(Object e) {
    final s = e.toString();
    return s.length <= 80 ? s : '${s.substring(0, 77)}...';
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: CleartextTrafficAllowedScreen.vulnId,
      title: 'Cleartext Traffic Allowed',
      difficulty: DvmaDifficulty.easy,
      explanation:
          'The app posts credentials to an http:// endpoint and the platform '
          'config permits cleartext (usesCleartextTraffic=true / '
          'NSAllowsArbitraryLoads). This fires a request - point it at your '
          'mitmproxy/listener and the credentials appear verbatim on the wire.',
      children: [
        TextField(
          controller: _url,
          decoration: const InputDecoration(labelText: 'Endpoint URL'),
        ),
        DemoActionButton(
          label: _sending ? 'Sending…' : 'Send login request',
          onPressed: _sending ? () {} : () => _send(),
        ),
        if (_wire != null)
          EvidencePanel(label: 'on the wire (unencrypted)', value: _wire!),
      ],
    );
  }
}
