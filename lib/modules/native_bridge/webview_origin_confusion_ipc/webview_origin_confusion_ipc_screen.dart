import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'webview_ipc_dispatcher.dart';

/// WebView Origin Confusion -> Local-Only IPC.
///
/// The WebView IPC layer classifies the caller's origin with a sloppy
/// substring/contains check, so a REMOTE page whose host merely contains the
/// local host token is misclassified as the local/trusted application origin
/// and can invoke local-only, privileged IPC commands (Tauri WebView IPC
/// origin-confusion CVE-2026-42184 class).
class WebviewOriginConfusionIpcScreen extends StatefulWidget {
  const WebviewOriginConfusionIpcScreen({super.key});

  static const String vulnId = 'webview_origin_confusion_ipc';

  @override
  State<WebviewOriginConfusionIpcScreen> createState() =>
      _WebviewOriginConfusionIpcScreenState();
}

class _WebviewOriginConfusionIpcScreenState
    extends State<WebviewOriginConfusionIpcScreen> {
  static const String _localOrigin = WebViewIpcDispatcher.defaultLocalOrigin;

  // A REMOTE attacker page whose host contains `localhost` as a subdomain.
  static const String _remoteOrigin = 'https://tauri.localhost.evil.com';
  static const String _command = WebViewIpcDispatcher.privilegedCommand;

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

  /// Boots a real WebView exposing an `Ipc` channel. A page posts a privileged
  /// command tagged with an attacker-controlled origin whose host merely
  /// CONTAINS `localhost`; the dispatcher's loose contains() classifier treats
  /// it as local and runs the local-only command.
  Future<void> _bootRealWebView() async {
    try {
      final dispatcher = WebViewIpcDispatcher();
      final controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        ..addJavaScriptChannel(
          'Ipc',
          onMessageReceived: (JavaScriptMessage m) {
            final req = jsonDecode(m.message) as Map<String, dynamic>;
            // VULN: classify with the loose contains() check.
            final r = dispatcher.dispatch(
              command: req['command'] as String,
              callerOrigin: req['origin'] as String,
            );
            if (r.executed) {
              DvmaEvidence.record(
                WebviewOriginConfusionIpcScreen.vulnId,
                'webview-origin-confusion',
                'remote page ${req['origin']} misclassified as local; '
                    'local-only command ${req['command']} executed -> '
                    '${r.output}',
              );
            }
            _controller?.runJavaScript(
              'document.title=${_jsString('ipc=${r.output ?? r.blockReason}')}',
            );
            if (!mounted) return;
            setState(
              () => _liveResult =
                  'command=${req['command']} origin=${req['origin']}\n'
                  'classifiedLocal=${r.classifiedLocal} executed=${r.executed}\n'
                  'output=${r.output ?? '(none)'}',
            );
          },
        );
      await controller.loadHtmlString(
        '<html><body><h1>remote page</h1><script>'
        'Ipc.postMessage(JSON.stringify({command:${_jsString(_command)},'
        'origin:${_jsString(_remoteOrigin)}}));'
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

  String _render(IpcDispatchResult r) {
    final b = StringBuffer();
    b.writeln('local origin       : $_localOrigin');
    b.writeln('caller origin      : $_remoteOrigin');
    b.writeln('command            : $_command');
    b.writeln('classified local   : ${r.classifiedLocal}');
    b.writeln('executed           : ${r.executed}');
    b.writeln('blocked            : ${r.blocked}');
    if (r.blockReason != null) {
      b.writeln('block reason       : ${r.blockReason}');
    }
    b.writeln('command output     : ${r.output ?? '(none)'}');
    b.writeln(
      'privileged->remote : '
      '${r.privilegedReachedRemote(_remoteOrigin, _localOrigin)}',
    );
    return b.toString().trimRight();
  }

  void _run() {
    final dispatcher = WebViewIpcDispatcher();

    // VULN: the loose classifier treats the remote page as local and runs the
    // local-only privileged command.
    final vuln = dispatcher.dispatch(
      command: _command,
      callerOrigin: _remoteOrigin,
    );

    // SECURE: exact canonical-origin comparison rejects the remote page.
    final secure = dispatcher.dispatchSafe(
      command: _command,
      callerOrigin: _remoteOrigin,
    );

    setState(() {
      _vulnResult = _render(vuln);
      _secureResult = _render(secure);
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: WebviewOriginConfusionIpcScreen.vulnId,
      title: 'WebView Origin Confusion -> Local-Only IPC',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A WebView IPC layer decides "is this call from the local/trusted '
          'application origin?" before it will run local-only, privileged IPC '
          'commands (here $_command). The vulnerable classifier uses a sloppy '
          'substring/contains check, so a REMOTE page ($_remoteOrigin) - whose '
          'host merely CONTAINS the local host token "localhost" - is '
          'misclassified as the local origin ($_localOrigin) and the privileged '
          'command executes (Tauri WebView IPC origin-confusion CVE-2026-42184 '
          'class). This runs in a REAL WebView: the page posts the command '
          'with an attacker Origin over a native Ipc channel and the '
          'misclassified caller reaches the privileged command (the in-memory '
          'panels are the offline contrast). The secure path does an exact '
          'canonical-origin comparison '
          '(scheme + host + port) so only the true local origin is trusted.',
      children: [
        DemoActionButton(
          label: 'Invoke local-only IPC command from remote page',
          onPressed: _run,
        ),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'IPC dispatch (loose contains() origin check)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'validated: exact canonical-origin comparison',
            value: _secureResult!,
          ),
        if (_liveResult != null)
          EvidencePanel(
            label: 'REAL webview: remote page ran local-only IPC command',
            value: _liveResult!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
