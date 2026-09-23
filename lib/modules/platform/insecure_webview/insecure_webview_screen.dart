import 'dart:io' show File;

import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';

/// Insecure WebView (JS Bridge RCE, file:// access).
///
/// WebView exposes a JS bridge and enables file:// access for RCE-style abuse.
/// Backed by a real Android System WebView: JavaScript is enabled, file access
/// is turned on, and a `Native` JavaScript channel is exposed with no origin
/// allow-list. Attacker-controlled page script calls `Native.postMessage(...)`
/// and the native handler answers with app secrets / on-device file contents.
class InsecureWebviewScreen extends StatefulWidget {
  const InsecureWebviewScreen({super.key});

  static const String vulnId = 'insecure_webview';

  @override
  State<InsecureWebviewScreen> createState() => _InsecureWebviewScreenState();
}

class _InsecureWebviewScreenState extends State<InsecureWebviewScreen> {
  // The insecure WebView settings (native-level, enabled below on a device).
  static const bool javaScriptEnabled = true;
  static const bool allowFileAccess = true; // setAllowFileAccess / file://
  static const bool jsBridgeExposed = true; // Native JS channel, no allow-list

  /// The app "secret" the exposed bridge will hand back to any page.
  static const String _bridgeSecret =
      '<string name="token">DVMA{webview_bridge_rce}</string>';

  final _js = TextEditingController(
    text: "Native.postMessage('readFile:auth.xml')",
  );

  WebViewController? _controller;
  String? _result;

  @override
  void initState() {
    super.initState();
    if (!supportsRealWebView) return;

    final controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      // VULN: expose a native bridge with no origin allow-list. Whatever the
      // (attacker-controlled) page posts runs with app privileges and the
      // native side returns app secrets / file contents to the page.
      ..addJavaScriptChannel(
        'Native',
        onMessageReceived: (JavaScriptMessage msg) {
          _onBridgeCall(msg.message);
        },
      );

    // VULN: file:// access on so bridge / page can read on-device files.
    final platform = controller.platform;
    if (platform is AndroidWebViewController) {
      platform.setAllowFileAccess(true);
    }

    // Load a page that immediately invokes the exposed bridge (this is what a
    // malicious/MITM'd page would do): call Native.postMessage with a file read.
    controller.loadHtmlString(
      '<html><body><h1>partner page</h1>'
      '<script>Native.postMessage("readFile:auth.xml");'
      'Native.postMessage("getToken");</script></body></html>',
    );
    _controller = controller;
  }

  /// The exposed bridge handler. Runs with app privileges; no allow-list.
  Future<void> _onBridgeCall(String call) async {
    String out;
    if (call.startsWith('readFile:')) {
      out = await _readFileForBridge(call.substring('readFile:'.length));
    } else if (call == 'getToken') {
      // Route through the same real file read so the token the bridge hands to
      // page JS is genuine on-disk contents (adb-pullable), not a constant.
      final body = await _readFileForBridge('token.xml');
      out = 'bridge returned token via $body';
    } else {
      out = 'bridge invoked with app privileges: $call';
    }
    // The secret / file contents left the app boundary to page-controlled JS.
    DvmaEvidence.record(
      InsecureWebviewScreen.vulnId,
      'webview-bridge',
      'Native.postMessage($call) -> $out',
    );
    if (!mounted) return;
    setState(() => _result = out);
  }

  /// Reads a real on-device file for the bridge (best effort). This is the
  /// app's own sandbox file, the bridge exposes it to arbitrary page script.
  Future<String> _readFileForBridge(String name) async {
    try {
      final dir = await DvmaEvidence.artifactDirPath();
      if (dir != null) {
        // Seed + read a real file so the bridge returns genuine disk contents.
        final f = File('$dir/insecure_webview_$name');
        if (!await f.exists()) {
          await f.writeAsString(_bridgeSecret, flush: true);
        }
        final body = await f.readAsString();
        return 'bridge read ${f.path}:\n$body';
      }
    } catch (_) {
      // fall through to the seeded secret
    }
    return 'bridge returned file contents:\n$_bridgeSecret';
  }

  /// Manually invoke the exposed bridge from the JS the trainee typed, using
  /// the real WebView JS engine (runJavaScript executes it in page context).
  void _runFromPage() {
    final call = _js.text.trim();
    final controller = _controller;
    if (controller == null) {
      // No real WebView (test/web/desktop): still exercise the bridge handler.
      _onBridgeCall(_extractBridgeArg(call));
      return;
    }
    // Execute the attacker JS inside the live WebView; it calls back into the
    // exposed Native channel just like a hostile page would.
    controller.runJavaScript(call);
  }

  /// Pull the argument out of a `Native.postMessage('x')` string for the
  /// no-WebView fallback path.
  static String _extractBridgeArg(String call) {
    final start = call.indexOf(RegExp("['\"]"));
    final end = call.lastIndexOf(RegExp("['\"]"));
    if (start >= 0 && end > start) return call.substring(start + 1, end);
    return call;
  }

  @override
  void dispose() {
    _js.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: InsecureWebviewScreen.vulnId,
      title: 'Insecure WebView (JS Bridge RCE)',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'The WebView enables JavaScript, file:// access, and a native JS '
          'bridge (addJavaScriptChannel "Native") with no origin allow-list, so '
          'a malicious/MITM\'d page calls into app internals (read files, invoke '
          'native methods) - RCE-style abuse. This runs a REAL Android System '
          'WebView: the loaded page posts to the exposed Native channel and the '
          'native handler returns the app secret / on-device file to page JS.',
      children: [
        EvidencePanel(
          label: 'webview settings',
          value:
              'javaScriptEnabled = $javaScriptEnabled\n'
              'allowFileAccess = $allowFileAccess\n'
              'jsBridge("Native") exposed = $jsBridgeExposed',
        ),
        TextField(
          controller: _js,
          decoration: const InputDecoration(labelText: 'JS the page runs'),
        ),
        DemoActionButton(label: 'Run from page', onPressed: _runFromPage),
        if (_result != null)
          EvidencePanel(
            label: 'bridge result (app privileges)',
            value: _result!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
