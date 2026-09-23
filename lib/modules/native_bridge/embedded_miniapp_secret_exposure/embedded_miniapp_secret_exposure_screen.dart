import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import '../../../core/webview_demo_host.dart';
import 'mini_app_store.dart';

/// Embedded Mini-App Secret Exposure.
///
/// An embedded web-app / Mini-App persists plaintext, replayable auth tokens
/// (and recovery secrets such as wallet mnemonics) in WebView storage reachable
/// over the JS<->native bridge with no origin isolation, so any embedded
/// content or co-resident inspector reads and replays them (Telegram Mini App /
/// TENET research class).
class EmbeddedMiniappSecretExposureScreen extends StatefulWidget {
  const EmbeddedMiniappSecretExposureScreen({super.key});

  static const String vulnId = 'embedded_miniapp_secret_exposure';

  @override
  State<EmbeddedMiniappSecretExposureScreen> createState() =>
      _EmbeddedMiniappSecretExposureScreenState();
}

class _EmbeddedMiniappSecretExposureScreenState
    extends State<EmbeddedMiniappSecretExposureScreen> {
  // A co-resident inspector / injected script running in the WebView under a
  // different origin than the Mini-App it is stealing from.
  static const String _attackerOrigin = 'https://evil.miniapp.example';

  String? _vuln;
  String? _secure;

  WebViewController? _controller;
  String? _liveResult;

  @override
  void initState() {
    super.initState();
    if (!supportsRealWebView) return;
    _bootRealWebView();
  }

  /// Boots a real WebView where the Mini-App persists its PLAINTEXT, replayable
  /// auth token and wallet mnemonic in WebView localStorage, then a co-resident
  /// script (the attacker origin, same WebView) reads them straight back out.
  Future<void> _bootRealWebView() async {
    try {
      final controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        ..addJavaScriptChannel(
          'Steal',
          onMessageReceived: (JavaScriptMessage m) {
            DvmaEvidence.record(
              EmbeddedMiniappSecretExposureScreen.vulnId,
              'webview-miniapp-secret',
              'co-resident script read plaintext Mini-App secrets from WebView '
                  'localStorage (no origin isolation) -> ${m.message}',
            );
            if (!mounted) return;
            setState(
              () => _liveResult =
                  'co-resident script read from storage:\n${m.message}',
            );
          },
        );
      // Mini-App persists the raw secrets into WebView storage.
      await controller.loadHtmlString(
        '<html><body><h1>mini-app</h1><script>'
        'localStorage.setItem("auth_token",${_jsString(MiniAppStore.authToken)});'
        'localStorage.setItem("wallet_mnemonic",'
        '${_jsString(MiniAppStore.walletMnemonic)});'
        // Co-resident/injected script reads them straight back out.
        'Steal.postMessage("auth_token="+localStorage.getItem("auth_token")'
        '+"; wallet_mnemonic="+localStorage.getItem("wallet_mnemonic"));'
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

  void _run() {
    final store = MiniAppStore();

    // VULN: the attacker origin calls the bridge getter and reads the plaintext
    // token + mnemonic straight out of WebView storage, then replays the token.
    final leak = store.getStoredAuth(
      const BridgeRequest(callerOrigin: _attackerOrigin),
    );
    final vulnBuf = StringBuffer()
      ..writeln('caller origin : $_attackerOrigin')
      ..writeln('bridge method : getStoredAuth()')
      ..writeln('granted       : ${leak.granted}')
      ..writeln('auth token    : ${leak.token ?? '(none)'}')
      ..writeln('wallet mnemonic : ${leak.mnemonic ?? '(none)'}')
      ..writeln('replayable    : ${leak.token != null}')
      ..writeln('secret exposed: ${leak.secretExposed}');

    // SECURE: the Mini-App origin mints a single-use, origin-bound handle. The
    // attacker origin then tries to replay that handle from its own origin.
    final mint = store.mintAuthHandle(
      const BridgeRequest(callerOrigin: MiniAppStore.defaultTrustedOrigin),
    );
    final replay = store.redeemAuthHandle(
      BridgeRequest(callerOrigin: _attackerOrigin, handle: mint.handle),
    );
    // The legitimate origin can redeem it exactly once.
    final legit = store.redeemAuthHandle(
      BridgeRequest(
        callerOrigin: MiniAppStore.defaultTrustedOrigin,
        handle: mint.handle,
      ),
    );
    final secureBuf = StringBuffer()
      ..writeln('minted handle : ${mint.handle ?? '(none)'}')
      ..writeln('mnemonic over bridge : never (stays native-side)')
      ..writeln('--- cross-origin replay ($_attackerOrigin) ---')
      ..writeln('granted       : ${replay.granted}')
      ..writeln('token         : ${replay.token ?? '(none)'}')
      ..writeln('reason        : ${replay.reason}')
      ..writeln('--- legitimate single-use redeem ---')
      ..writeln('granted       : ${legit.granted}')
      ..writeln('token         : ${legit.token ?? '(none)'}');

    setState(() {
      _vuln = vulnBuf.toString().trimRight();
      _secure = secureBuf.toString().trimRight();
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: EmbeddedMiniappSecretExposureScreen.vulnId,
      title: 'Embedded Mini-App Secret Exposure',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'An embedded Mini-App persists PLAINTEXT, REPLAYABLE auth tokens - '
          'and a recovery secret such as a wallet mnemonic - in WebView storage '
          'reachable over the JS<->native bridge with NO origin isolation. So a '
          'co-resident inspector / injected script under another origin '
          '($_attackerOrigin) calls the bridge getter, reads the plaintext '
          'token and mnemonic, and replays the token (Telegram Mini App / TENET '
          'research class). This persists the token + mnemonic in a REAL '
          'WebView storage and reads them back over a native JS bridge (the '
          'in-memory panel is the offline contrast). The secure path never '
          'persists the raw '
          'token or mnemonic in WebView-reachable storage: it mints a '
          'short-lived, origin-bound, single-use handle, so a replay from '
          'another origin (or a second time) fails and the mnemonic is never '
          'reachable over the bridge.',
      children: [
        DemoActionButton(
          label: 'Read Mini-App storage from co-resident origin',
          onPressed: _run,
        ),
        if (_vuln != null)
          EvidencePanel(
            label: 'bridge.getStoredAuth (plaintext, replayable)',
            value: _vuln!,
          ),
        if (_secure != null)
          EvidencePanel(
            label: 'origin-bound single-use handle (replay fails)',
            value: _secure!,
          ),
        if (_liveResult != null)
          EvidencePanel(
            label: 'REAL webview: plaintext secrets read from localStorage',
            value: _liveResult!,
          ),
        RealWebViewView(controller: _controller),
      ],
    );
  }
}
