import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'callback_bridge.dart';

/// JS Bridge Callback-ID Injection.
///
/// A Cordova-style native bridge trusts a caller-supplied `callbackId` and
/// dispatches a plugin's native result to whatever id the web message names,
/// without verifying the id belongs to the requesting plugin. Attacker JS in an
/// unprivileged plugin forges the privileged Camera plugin's id and receives
/// its result (Cordova InAppBrowser iOS CVE-2026-47430 class).
class JsBridgeCallbackIdInjectionScreen extends StatefulWidget {
  const JsBridgeCallbackIdInjectionScreen({super.key});

  static const String vulnId = 'js_bridge_callback_id_injection';

  @override
  State<JsBridgeCallbackIdInjectionScreen> createState() =>
      _JsBridgeCallbackIdInjectionScreenState();
}

class _JsBridgeCallbackIdInjectionScreenState
    extends State<JsBridgeCallbackIdInjectionScreen> {
  // Attacker-controlled unprivileged plugin that forges the Camera id.
  static const String _attackerPlugin = 'Console';

  String? _vulnResult;
  String? _secureResult;

  WebViewController? _controller;
  String? _liveResult;

  @override
  void initState() {
    super.initState();
    if (!supportsRealWebView) return;
    _bootRealWebView();
  }

  /// Boots a real WebView with a Cordova-style `NativeBridge` channel. The page
  /// (running as the unprivileged Console plugin) forges the privileged Camera
  /// plugin's callbackId; the native side dispatches WITHOUT an ownership check
  /// and delivers the Camera result back into the attacker's JS handler.
  Future<void> _bootRealWebView() async {
    try {
      final bridge = CallbackBridge.withPlugins();
      final controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        // The exposed dispatch entry-point: page posts {callbackId, plugin}.
        ..addJavaScriptChannel(
          'NativeBridge',
          onMessageReceived: (JavaScriptMessage m) {
            final req = jsonDecode(m.message) as Map<String, dynamic>;
            final r = bridge.dispatch(
              callbackId: req['callbackId'] as String,
              requestingPlugin: req['plugin'] as String,
              payload: CallbackBridge.cameraResult,
            );
            if (r.delivered) {
              DvmaEvidence.record(
                JsBridgeCallbackIdInjectionScreen.vulnId,
                'webview-callback-injection',
                'Console plugin forged ${req['callbackId']} (owned by Camera); '
                    'native delivered Camera result to ${r.deliveredToPlugin} '
                    '-> ${r.payload}',
              );
              // Deliver the native result back into the page's handler.
              _controller?.runJavaScript(
                'window.onNative(${_jsString(r.payload ?? '')})',
              );
            }
          },
        )
        // Where the page reports what its (attacker) handler received.
        ..addJavaScriptChannel(
          'Received',
          onMessageReceived: (JavaScriptMessage m) {
            if (!mounted) return;
            setState(
              () => _liveResult =
                  'Console plugin handler received Camera result:\n${m.message}',
            );
          },
        );
      await controller.loadHtmlString(
        '<html><body><h1>console plugin</h1><script>'
        'window.onNative=function(p){Received.postMessage(p)};'
        'NativeBridge.postMessage(JSON.stringify('
        '{callbackId:${_jsString(CallbackBridge.cameraCallbackId)},'
        'plugin:${_jsString(_attackerPlugin)}}));'
        '</script></body></html>',
      );
      if (!mounted) return;
      setState(() => _controller = controller);
    } catch (_) {
      // Best effort; helper contrast panels still demonstrate the flaw.
    }
  }

  /// Quote a Dart string as a JS string literal.
  static String _jsString(String s) =>
      '"${s.replaceAll(r'\', r'\\').replaceAll('"', r'\"')}"';

  String _render(DispatchResult r, RegisteredCallback owner) {
    final b = StringBuffer();
    b.writeln('forged callbackId : ${CallbackBridge.cameraCallbackId}');
    b.writeln(
      'owned by plugin   : ${owner.pluginId} '
      '(privileged=${owner.privileged})',
    );
    b.writeln('requesting plugin : $_attackerPlugin');
    b.writeln('delivered         : ${r.delivered}');
    b.writeln('blocked           : ${r.blocked}');
    if (r.blockReason != null) {
      b.writeln('block reason      : ${r.blockReason}');
    }
    if (r.delivered) {
      b.writeln('delivered to      : ${r.deliveredToPlugin}');
      b.writeln('payload           : ${r.payload}');
    }
    b.writeln(
      'cross-plugin leak : '
      '${r.crossPluginLeak(owner, _attackerPlugin)}',
    );
    return b.toString().trimRight();
  }

  void _run() {
    final bridge = CallbackBridge.withPlugins();
    final owner = bridge.callback(CallbackBridge.cameraCallbackId)!;

    // VULN: unprivileged Console plugin forges the Camera callback id and the
    // bridge dispatches the Camera result into the attacker's handler.
    final vuln = bridge.dispatch(
      callbackId: CallbackBridge.cameraCallbackId,
      requestingPlugin: _attackerPlugin,
      payload: CallbackBridge.cameraResult,
    );

    // SECURE: format + ownership validation refuses the forged id.
    final secure = bridge.dispatchSafe(
      callbackId: CallbackBridge.cameraCallbackId,
      requestingPlugin: _attackerPlugin,
      payload: CallbackBridge.cameraResult,
    );

    setState(() {
      _vulnResult = _render(vuln, owner);
      _secureResult = _render(secure, owner);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: JsBridgeCallbackIdInjectionScreen.vulnId,
      title: 'JS Bridge Callback-ID Injection',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A Cordova-style native bridge lets each JS plugin register a native '
          'callback keyed by a caller-supplied callbackId. When a plugin '
          'resolves, the native side dispatches the result to whatever '
          'callbackId the web message names, WITHOUT verifying the id belongs '
          'to the requesting plugin. So attacker JS running as the unprivileged '
          'Console plugin forges the privileged Camera plugin\'s callbackId and '
          'receives the Camera result (a photo URI + bytes) into its own '
          'handler (Cordova InAppBrowser iOS CVE-2026-47430 class). This runs '
          'in a REAL WebView: the page forges the Camera callbackId over a '
          'native JS channel and the native side delivers the Camera result '
          'into the attacker\'s handler (the in-memory panels are the offline '
          'contrast). The secure path validates the callbackId format '
          'with a strict regex AND checks that the id was registered by the '
          'requesting plugin, so the forged id is refused.',
      children: [
        DemoActionButton(
          label: 'Forge Camera callbackId from Console plugin',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'bridge.dispatch (no id ownership check)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'validated: callbackId regex + plugin ownership',
            value: _secureResult!,
          ),
        if (_liveResult != null)
          EvidencePanel(
            label: 'REAL webview: forged Camera id delivered to Console',
            value: _liveResult!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
