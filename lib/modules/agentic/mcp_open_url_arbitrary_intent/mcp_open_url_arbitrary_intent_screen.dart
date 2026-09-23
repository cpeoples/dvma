import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/platform_ipc_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'mcp_open_url_host.dart';

/// MCP open_url -> Arbitrary Android Intent.
///
/// An MCP tool the agent can invoke (`mobile_open_url`) maps a model-supplied
/// url straight to Android `startActivity()` with no scheme allowlist, so a
/// prompt-injected agent fires dangerous intents (`tel:`/`sms:`/`content://`/
/// `intent://`) and reaches privileged, cross-app actions (Mobile MCP
/// CVE-2026-35394 class).
class McpOpenUrlArbitraryIntentScreen extends StatefulWidget {
  const McpOpenUrlArbitraryIntentScreen({super.key});

  static const String vulnId = 'mcp_open_url_arbitrary_intent';

  @override
  State<McpOpenUrlArbitraryIntentScreen> createState() =>
      _McpOpenUrlArbitraryIntentScreenState();
}

class _McpOpenUrlArbitraryIntentScreenState
    extends State<McpOpenUrlArbitraryIntentScreen> {
  // A prompt-injection string is the default so the privileged intent fires on
  // load: the agent is steered to hand a `tel:` url to `mobile_open_url`.
  final _input = TextEditingController(text: McpToolHost.injectedTelPrompt);

  WebViewController? _controller;
  OpenUrlOutcome? _vuln;
  OpenUrlOutcome? _secure;
  bool _running = false;

  @override
  void initState() {
    super.initState();
    if (supportsRealWebView) {
      _controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted);
    }
  }

  Future<void> _run() async {
    if (_running) return;
    setState(() => _running = true);
    // Each run uses a fresh host so the recorded intents reflect this run. A
    // real model chooses the url; a web-scheme choice drives a real WebView
    // navigation (a genuine on-device visit to the model-chosen target), and a
    // non-web scheme fires a real startActivity(ACTION_VIEW) via the platform
    // bridge, the native result is what the evidence reports.
    final vuln = await McpToolHost().openUrlLive(
      _input.text,
      navigateWeb: (uri) async => _controller?.loadRequest(uri),
      launchNonWeb: (url) => PlatformIpcBridge.launchExternalUrl(url),
    );
    // Even with the user "confirming", the secure tool refuses non-web schemes.
    final secure = McpToolHost().openUrlSafe(_input.text, userConfirmed: true);
    if (!mounted) return;
    setState(() {
      _vuln = vuln;
      _secure = secure;
      _running = false;
    });
    // Evidence: fires when the agent's mobile_open_url call dispatched a
    // model-supplied url to startActivity() with no scheme allowlist. When the
    // real native bridge answered on-device, the recorded effect IS the native
    // startActivity result; otherwise it's the offline in-memory fallback.
    if (vuln.fired && vuln.url != null) {
      final effect = vuln.firedRealIntent
          ? 'real native startActivity: ${vuln.nativeResult}'
          : 'offline fallback (no device): '
                'startActivity(${vuln.system.fired.join(", ")})';
      DvmaEvidence.record(
        McpOpenUrlArbitraryIntentScreen.vulnId,
        'open-url',
        'mobile_open_url dispatched to startActivity() (no allowlist): '
            '${vuln.url}'
            '${vuln.firedDangerousIntent ? " [dangerous scheme: ${vuln.scheme}:]" : ""}'
            '\n$effect',
      );
    }
  }

  @override
  void dispose() {
    _input.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: McpOpenUrlArbitraryIntentScreen.vulnId,
      title: 'MCP open_url -> Arbitrary Android Intent',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'An MCP tool the agent can invoke - mobile_open_url - takes a '
          'MODEL-SUPPLIED url and maps it straight to Android startActivity() '
          'with NO scheme allowlist and NO confirmation. Because a '
          'prompt-injected agent controls that argument, it can fire dangerous '
          'intents (tel:, sms:, content://, intent://) that reach privileged, '
          'cross-app actions - dialing a premium line, reading a content '
          'provider, or launching an arbitrary intent on the user\'s behalf '
          '(Mobile MCP CVE-2026-35394 class). A REAL model chooses the url; a '
          'web-scheme choice is navigated by a REAL WebView. The secure path '
          'allows only https/http, refuses every privileged scheme, and '
          'requires explicit user confirmation, so a model argument alone can '
          'never dispatch a privileged intent.',
      children: [
        TextField(
          controller: _input,
          maxLines: 4,
          decoration: const InputDecoration(
            labelText: 'Prompt-injection that steers the mobile_open_url arg',
          ),
        ),
        DemoActionButton(
          label: _running
              ? 'Calling mobile_open_url...'
              : 'Let the agent call mobile_open_url',
          onPressed: _run,
        ),
        if (_vuln != null) ...[
          EvidencePanel(
            label: 'VULN model-supplied url argument',
            value: _vuln!.url ?? '(none)',
          ),
          EvidencePanel(
            label: 'VULN intent fired?',
            value: _vuln!.fired
                ? (_vuln!.firedRealIntent
                      ? 'YES - real native startActivity: ${_vuln!.nativeResult}'
                      : 'YES - startActivity(${_vuln!.system.fired.join(", ")}) '
                            '(offline fallback)')
                : 'no (${_vuln!.reason})',
          ),
          EvidencePanel(
            label: 'VULN dangerous cross-app intent reached?',
            value: _vuln!.firedDangerousIntent
                ? 'YES - privileged "${_vuln!.scheme}:" intent '
                      '${_vuln!.firedRealIntent ? "dispatched on-device" : "dispatched (offline)"}'
                : 'no',
          ),
          RealWebViewView(controller: _controller),
        ],
        if (_secure != null) ...[
          EvidencePanel(label: 'SECURE decision', value: _secure!.reason),
          EvidencePanel(
            label: 'SECURE intent fired?',
            value: _secure!.fired ? 'YES (unexpected!)' : 'no - blocked',
          ),
        ],
      ],
    );
  }
}
