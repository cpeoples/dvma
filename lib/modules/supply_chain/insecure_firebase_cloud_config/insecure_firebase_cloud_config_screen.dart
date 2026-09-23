import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:provider/provider.dart';

import '../../../app_config.dart';
import '../../../core/evidence_sink.dart';
import '../../../core/platform_lingo.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'firebase_cloud_config.dart';

/// Insecure Firebase / Cloud Backend Config.
///
/// A world-readable Firebase/cloud backend URL plus hardcoded cloud credentials
/// expose backend data.
class InsecureFirebaseCloudConfigScreen extends StatefulWidget {
  const InsecureFirebaseCloudConfigScreen({super.key});

  static const String vulnId = 'insecure_firebase_cloud_config';

  @override
  State<InsecureFirebaseCloudConfigScreen> createState() =>
      _InsecureFirebaseCloudConfigScreenState();
}

class _InsecureFirebaseCloudConfigScreenState
    extends State<InsecureFirebaseCloudConfigScreen> {
  String? _config;
  String? _vulnResult;
  String? _secureResult;

  Future<void> _run() async {
    final all = FirebaseCloudConfig.fetchAllRecords();
    // Secure read, logged in as alice, only returns alice's own record.
    final secure = FirebaseCloudConfig.secureFetchOwnRecords(
      userId: 'alice',
      token: 'valid-session-token',
    );

    // VULN: the unauthenticated read really hits the exposed backend. This GET
    // (no token, no auth header) crosses the wire, the analogue of
    // `curl https://<db>.firebaseio.com/users.json`, and is observable in
    // mitmproxy/tcpdump.
    final base = context.read<AppConfig>().captureBase;
    final url = '$base/config';
    var fetched = '';
    try {
      final resp = await http
          .get(Uri.parse(url))
          .timeout(const Duration(seconds: 6));
      final body = resp.body.length > 300
          ? '${resp.body.substring(0, 300)}…'
          : resp.body;
      fetched = 'GET $url -> HTTP ${resp.statusCode}\n$body';
    } catch (err) {
      fetched = 'GET $url -> no response ($err)';
    }

    // Mirror the exposed config read + the hardcoded creds recovered from the
    // binary (fire-and-forget).
    DvmaEvidence.record(
      InsecureFirebaseCloudConfigScreen.vulnId,
      'cloud-config',
      'GET $url\n'
          'db=${FirebaseCloudConfig.databaseUrl}\n'
          'apiKey=${FirebaseCloudConfig.apiKey}\n'
          'cloudSecret=${FirebaseCloudConfig.cloudSecret}\n'
          '$fetched',
    );

    if (!mounted) return;
    setState(() {
      _config =
          'db:  ${FirebaseCloudConfig.databaseUrl}\n'
          'key: ${FirebaseCloudConfig.apiKey}\n'
          'rules: .read=true .write=true (public)\n\n'
          '-> unauth read of $url:\n$fetched';
      _vulnResult = all.entries.map((e) => '${e.key}: ${e.value}').join('\n');
      _secureResult = 'alice (authenticated): $secure';
    });
  }

  @override
  Widget build(BuildContext context) {
    final lingo = PlatformLingo.current();
    return VulnDemoScaffold(
      vulnId: InsecureFirebaseCloudConfigScreen.vulnId,
      title: 'Insecure Firebase Config',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'The Firebase database URL and cloud API key/secret are hardcoded in '
          'the app (recoverable with ${lingo.reverseTools}) and the backend '
          'rules are '
          'world-readable (.read=true). An unauthenticated read therefore '
          'returns every user\'s records, not just the caller\'s. The real '
          'check is hitting the exposed endpoint, e.g. '
          'curl https://<db>.firebaseio.com/users.json. A secure backend '
          'requires auth and scopes reads to the owner.',
      children: [
        DemoActionButton(label: 'Read cloud DB (no auth)', onPressed: _run),
        if (_config != null)
          EvidencePanel(label: 'hardcoded cloud config', value: _config!),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'unauthenticated read (all users)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'what an authenticated, scoped read returns',
            value: _secureResult!,
          ),
      ],
    );
  }
}
