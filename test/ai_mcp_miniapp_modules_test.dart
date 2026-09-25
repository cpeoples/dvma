import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/agentic/mcp_open_url_arbitrary_intent/mcp_open_url_host.dart';
import 'package:dvma/modules/ai_mobile/accessibility_tree_prompt_injection/a11y_perception.dart';
import 'package:dvma/modules/native_bridge/embedded_miniapp_secret_exposure/mini_app_store.dart';

/// Regression suite for the MCP / on-device-agent / Mini-App modules. Each test
/// asserts the INSECURE path fires/leaks/obeys the attacker payload AND that
/// the secure contrast blocks it, so an accidental "fix" of the lab fails CI.
void main() {
  group('mcp_open_url_arbitrary_intent', () {
    test('model-supplied tel: url fires a privileged intent; safe refuses it', () {
      // VULN: the prompt-injected agent hands a tel: url to mobile_open_url and
      // it is dispatched to startActivity() with no scheme allowlist.
      final vuln = McpToolHost().openUrl(McpToolHost.injectedTelPrompt);
      expect(vuln.fired, isTrue);
      expect(vuln.url, startsWith('tel:'));
      expect(vuln.scheme, 'tel');
      expect(vuln.firedDangerousIntent, isTrue);
      expect(vuln.system.fired, isNotEmpty);

      // VULN: a content:// URI reaches a cross-app content provider too.
      final vulnContent = McpToolHost().openUrl(
        McpToolHost.injectedContentPrompt,
      );
      expect(vulnContent.fired, isTrue);
      expect(vulnContent.scheme, 'content');
      expect(vulnContent.firedDangerousIntent, isTrue);

      // SECURE: even with the user "confirming", the dangerous scheme is
      // refused before the intent system is touched.
      final secure = McpToolHost().openUrlSafe(
        McpToolHost.injectedTelPrompt,
        userConfirmed: true,
      );
      expect(secure.fired, isFalse);
      expect(secure.firedDangerousIntent, isFalse);
      expect(secure.system.fired, isEmpty);
      expect(secure.reason, contains('not on the web allowlist'));
    });

    test('secure path dispatches an https url only after confirmation', () {
      const req = 'Open mobile_open_url with url = https://dvma.example/help';

      final confirmed = McpToolHost().openUrlSafe(req, userConfirmed: true);
      expect(confirmed.fired, isTrue);
      expect(confirmed.scheme, 'https');
      expect(confirmed.firedDangerousIntent, isFalse);

      // ...but not without confirmation.
      final unconfirmed = McpToolHost().openUrlSafe(req, userConfirmed: false);
      expect(unconfirmed.fired, isFalse);
      expect(unconfirmed.reason, contains('confirmation'));
    });
  });

  group('accessibility_tree_prompt_injection', () {
    test('injected a11y node redirects the agent; safe treats UI as data', () {
      final perceiver = AgentPerceiver();
      final tree = AgentPerceiver.maliciousTree();

      // VULN: all node text is concatenated straight into the prompt, so the
      // injected imperative is obeyed and the agent takes the unauthorized
      // action.
      final vuln = perceiver.perceiveInsecure(tree);
      expect(vuln.agentHijacked, isTrue);
      expect(vuln.action.performed, isTrue);
      expect(vuln.response.toolCall, isNotNull);
      expect(vuln.prompt, contains('SYSTEM OVERRIDE'));

      // SECURE: perceived UI is quoted as untrusted DATA and imperative nodes
      // are screened out, so the agent is never redirected.
      final secure = perceiver.perceiveSecure(tree);
      expect(secure.agentHijacked, isFalse);
      expect(secure.action.performed, isFalse);
      expect(secure.response.toolCall, isNull);
      // The injected instruction was stripped from the built prompt.
      expect(secure.prompt.contains('send_message'), isFalse);
    });

    test('benign-only tree never triggers an action', () {
      final perceiver = AgentPerceiver();
      const benign = [
        A11yNode(role: 'header', text: 'Inbox', attackerControlled: false),
        A11yNode(
          role: 'listitem',
          text: 'Mom: dinner at 7?',
          attackerControlled: false,
        ),
      ];
      expect(perceiver.perceiveInsecure(benign).agentHijacked, isFalse);
      expect(perceiver.perceiveSecure(benign).agentHijacked, isFalse);
    });
  });

  group('embedded_miniapp_secret_exposure', () {
    const attacker = 'https://evil.miniapp.example';

    test('co-resident origin reads plaintext token + mnemonic; safe blocks '
        'replay', () {
      final store = MiniAppStore();

      // VULN: any embedded origin reads the plaintext, replayable token AND the
      // wallet mnemonic straight out of WebView storage.
      final leak = store.getStoredAuth(
        const BridgeRequest(callerOrigin: attacker),
      );
      expect(leak.granted, isTrue);
      expect(leak.token, MiniAppStore.authToken);
      expect(leak.mnemonic, MiniAppStore.walletMnemonic);
      expect(leak.secretExposed, isTrue);

      // SECURE: the Mini-App origin mints a single-use, origin-bound handle.
      final mint = store.mintAuthHandle(
        const BridgeRequest(callerOrigin: MiniAppStore.defaultTrustedOrigin),
      );
      expect(mint.handle, isNotNull);
      // No secret material ever leaves over the mint call.
      expect(mint.token, isNull);
      expect(mint.mnemonic, isNull);

      // SECURE: a cross-origin replay of that handle fails.
      final replay = store.redeemAuthHandle(
        BridgeRequest(callerOrigin: attacker, handle: mint.handle),
      );
      expect(replay.granted, isFalse);
      expect(replay.blocked, isTrue);
      expect(replay.token, isNull);
      expect(replay.secretExposed, isFalse);

      // SECURE: the legitimate origin redeems it exactly once...
      final ok = store.redeemAuthHandle(
        BridgeRequest(
          callerOrigin: MiniAppStore.defaultTrustedOrigin,
          handle: mint.handle,
        ),
      );
      expect(ok.granted, isTrue);
      expect(ok.token, MiniAppStore.authToken);
      // ...and the mnemonic is never redeemable over the bridge.
      expect(ok.mnemonic, isNull);

      // SECURE: replaying the now-consumed handle a second time fails.
      final second = store.redeemAuthHandle(
        BridgeRequest(
          callerOrigin: MiniAppStore.defaultTrustedOrigin,
          handle: mint.handle,
        ),
      );
      expect(second.granted, isFalse);
      expect(second.blocked, isTrue);
    });

    test('untrusted origin cannot even mint a handle', () {
      final store = MiniAppStore();
      final mint = store.mintAuthHandle(
        const BridgeRequest(callerOrigin: attacker),
      );
      expect(mint.granted, isFalse);
      expect(mint.blocked, isTrue);
      expect(mint.handle, isNull);
    });
  });
}
