import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/native_bridge/js_bridge_callback_id_injection/callback_bridge.dart';
import 'package:dvma/modules/native_bridge/crossorigin_iframe_to_native_bridge/bridge_message_handler.dart';
import 'package:dvma/modules/native_bridge/js_bridge_exposes_privileged_api/privileged_bridge.dart';
import 'package:dvma/modules/native_bridge/qr_nfc_to_privileged_action/scan_action_dispatcher.dart';
import 'package:dvma/modules/native_bridge/exported_broadcast_receiver_spoof/broadcast_bus.dart';
import 'package:dvma/modules/native_bridge/webview_origin_confusion_ipc/webview_ipc_dispatcher.dart';
import 'package:dvma/modules/native_bridge/webview_js_injection_ssl_bypass/webview_loader.dart';

/// Regression suite for the Native / WebView Bridge training modules. Each test
/// asserts the *insecure* behavior is still present (so an accidental "fix"
/// fails CI) AND that the secure contrast blocks the attack.
void main() {
  group('js_bridge_callback_id_injection', () {
    test('forged callbackId delivers privileged result; safe rejects', () {
      final bridge = CallbackBridge.withPlugins();
      final owner = bridge.callback(CallbackBridge.cameraCallbackId)!;
      expect(owner.pluginId, 'Camera');
      expect(owner.privileged, isTrue);

      // VULN: unprivileged Console plugin forges the Camera callbackId and the
      // bridge dispatches the Camera result into the attacker's handler.
      final vuln = bridge.dispatch(
        callbackId: CallbackBridge.cameraCallbackId,
        requestingPlugin: 'Console',
        payload: CallbackBridge.cameraResult,
      );
      expect(vuln.delivered, isTrue);
      expect(vuln.blocked, isFalse);
      expect(vuln.deliveredToPlugin, 'Console');
      expect(vuln.payload, CallbackBridge.cameraResult);
      expect(vuln.crossPluginLeak(owner, 'Console'), isTrue);

      // SECURE: format + ownership validation refuses the forged id.
      final secure = bridge.dispatchSafe(
        callbackId: CallbackBridge.cameraCallbackId,
        requestingPlugin: 'Console',
        payload: CallbackBridge.cameraResult,
      );
      expect(secure.delivered, isFalse);
      expect(secure.blocked, isTrue);
      expect(secure.crossPluginLeak(owner, 'Console'), isFalse);

      // SECURE still delivers to the callbackId's true owner.
      final ok = bridge.dispatchSafe(
        callbackId: CallbackBridge.cameraCallbackId,
        requestingPlugin: 'Camera',
        payload: CallbackBridge.cameraResult,
      );
      expect(ok.delivered, isTrue);
      expect(ok.deliveredToPlugin, 'Camera');

      // SECURE also rejects a malformed callbackId outright.
      final malformed = bridge.dispatchSafe(
        callbackId: 'Camera; DROP TABLE',
        requestingPlugin: 'Camera',
        payload: CallbackBridge.cameraResult,
      );
      expect(malformed.blocked, isTrue);
    });
  });

  group('crossorigin_iframe_to_native_bridge', () {
    test('iframe exfiltrates token; safe requires main frame + origin', () {
      const trustedOrigin = 'https://app.dvma.example';
      final handler = BridgeMessageHandler(trustedOrigin: trustedOrigin);
      const iframeMsg = BridgeMessage(
        method: 'getAccessToken',
        frame: BridgeFrame.iframe,
        origin: 'https://ads.evil.example',
      );

      // VULN: cross-origin iframe posts to the bridge and gets the token.
      final vuln = handler.handle(iframeMsg);
      expect(vuln.handled, isTrue);
      expect(vuln.blocked, isFalse);
      expect(vuln.token, BridgeMessageHandler.accessToken);
      expect(vuln.tokenExfiltrated(iframeMsg, trustedOrigin), isTrue);

      // SECURE: iframe is refused before the token is returned.
      final secure = handler.handleSafe(iframeMsg);
      expect(secure.handled, isFalse);
      expect(secure.blocked, isTrue);
      expect(secure.token, isNull);
      expect(secure.tokenExfiltrated(iframeMsg, trustedOrigin), isFalse);

      // SECURE also refuses a main frame on an untrusted origin.
      const untrustedMain = BridgeMessage(
        method: 'getAccessToken',
        frame: BridgeFrame.mainFrame,
        origin: 'https://evil.example',
      );
      expect(handler.handleSafe(untrustedMain).blocked, isTrue);

      // SECURE still answers the trusted main frame.
      const trustedMain = BridgeMessage(
        method: 'getAccessToken',
        frame: BridgeFrame.mainFrame,
        origin: trustedOrigin,
      );
      final ok = handler.handleSafe(trustedMain);
      expect(ok.handled, isTrue);
      expect(ok.token, BridgeMessageHandler.accessToken);
      expect(ok.tokenExfiltrated(trustedMain, trustedOrigin), isFalse);
    });
  });

  group('js_bridge_exposes_privileged_api', () {
    test(
      'untrusted origin reads token/file; safe gates by origin + capability',
      () {
        final bridge = PrivilegedBridge();
        const attacker = 'https://ads.evil.example';

        // VULN: an untrusted ad origin calls getAuthToken() directly.
        final vuln = bridge.invoke(
          capability: BridgeCapability.readAuthToken,
          callerOrigin: attacker,
        );
        expect(vuln.invoked, isTrue);
        expect(vuln.value, PrivilegedBridge.authToken);
        expect(vuln.leakedTo(attacker, bridge.allowedOrigins), isTrue);

        // VULN: the same origin can also read a private file.
        final vulnFile = bridge.invoke(
          capability: BridgeCapability.readFile,
          callerOrigin: attacker,
          fileArg: PrivilegedBridge.secretFilePath,
        );
        expect(vulnFile.value, PrivilegedBridge.secretFileBody);
        expect(vulnFile.leakedTo(attacker, bridge.allowedOrigins), isTrue);

        // SECURE: origin allowlist denies the untrusted origin.
        final secure = bridge.invokeSafe(
          capability: BridgeCapability.readAuthToken,
          callerOrigin: attacker,
          grantedCapabilities: const {BridgeCapability.readAuthToken},
        );
        expect(secure.invoked, isFalse);
        expect(secure.blocked, isTrue);
        expect(secure.leakedTo(attacker, bridge.allowedOrigins), isFalse);

        // SECURE also denies a trusted origin lacking the capability grant.
        const trusted = 'https://app.dvma.example';
        final noCap = bridge.invokeSafe(
          capability: BridgeCapability.readAuthToken,
          callerOrigin: trusted,
          grantedCapabilities: const {},
        );
        expect(noCap.blocked, isTrue);

        // SECURE serves a trusted origin with the granted capability.
        final ok = bridge.invokeSafe(
          capability: BridgeCapability.readAuthToken,
          callerOrigin: trusted,
          grantedCapabilities: const {BridgeCapability.readAuthToken},
        );
        expect(ok.invoked, isTrue);
        expect(ok.value, PrivilegedBridge.authToken);
      },
    );
  });

  group('qr_nfc_to_privileged_action', () {
    test('untrusted scan fires action; safe needs trust + confirmation', () {
      const dispatcher = ScanActionDispatcher();
      const malicious = ScanEvent(
        source: ScanSource.nfc,
        callerPackage: 'com.evil.tagwriter',
        callerTrusted: false,
        action: ScanActionDispatcher.privilegedAction,
      );

      // VULN: the untrusted scan fires the automation immediately.
      final vuln = dispatcher.dispatch(malicious);
      expect(vuln.executed, isTrue);
      expect(vuln.blocked, isFalse);
      expect(vuln.executedAction, ScanActionDispatcher.privilegedAction);
      expect(vuln.silentlyTriggered(malicious), isTrue);

      // SECURE: untrusted source is refused.
      final secure = dispatcher.dispatchSafe(malicious);
      expect(secure.executed, isFalse);
      expect(secure.blocked, isTrue);
      expect(secure.silentlyTriggered(malicious), isFalse);

      // SECURE: a trusted source without confirmation is still refused.
      const trustedNoConfirm = ScanEvent(
        source: ScanSource.qr,
        callerPackage: 'com.dvma.app',
        callerTrusted: true,
        action: ScanActionDispatcher.privilegedAction,
        userConfirmed: false,
      );
      expect(dispatcher.dispatchSafe(trustedNoConfirm).blocked, isTrue);

      // SECURE fires only for a trusted, user-confirmed scan.
      const trustedConfirmed = ScanEvent(
        source: ScanSource.qr,
        callerPackage: 'com.dvma.app',
        callerTrusted: true,
        action: ScanActionDispatcher.privilegedAction,
        userConfirmed: true,
      );
      final ok = dispatcher.dispatchSafe(trustedConfirmed);
      expect(ok.executed, isTrue);
      expect(ok.executedAction, ScanActionDispatcher.privilegedAction);
    });
  });

  group('exported_broadcast_receiver_spoof', () {
    test('spoofed broadcast is trusted; safe checks sender + permission', () {
      final bus = BroadcastBus();
      const spoof = Broadcast(
        action: BroadcastBus.locationAction,
        senderPackage: 'com.evil.locationspoof',
        senderHoldsPermission: false,
        extras: {'lat': '40.6892', 'lon': '-74.0445'},
      );

      // VULN: exported receiver trusts the spoofed extras.
      final vuln = bus.deliver(spoof);
      expect(vuln.accepted, isTrue);
      expect(vuln.blocked, isFalse);
      expect(vuln.appliedExtras?['lat'], '40.6892');
      expect(vuln.spoofAccepted(spoof, bus.trustedSenders), isTrue);

      // SECURE: untrusted sender is rejected.
      final secure = bus.deliverSafe(spoof);
      expect(secure.accepted, isFalse);
      expect(secure.blocked, isTrue);
      expect(secure.spoofAccepted(spoof, bus.trustedSenders), isFalse);

      // SECURE: a trusted sender without the permission is still rejected.
      const trustedNoPerm = Broadcast(
        action: BroadcastBus.locationAction,
        senderPackage: 'com.dvma.app',
        senderHoldsPermission: false,
        extras: {'lat': '1.0', 'lon': '2.0'},
      );
      expect(bus.deliverSafe(trustedNoPerm).blocked, isTrue);

      // SECURE accepts a trusted sender holding the signature permission.
      const trusted = Broadcast(
        action: BroadcastBus.locationAction,
        senderPackage: 'com.dvma.app',
        senderHoldsPermission: true,
        extras: {'lat': '37.7749', 'lon': '-122.4194'},
      );
      final ok = bus.deliverSafe(trusted);
      expect(ok.accepted, isTrue);
      expect(ok.appliedExtras?['lat'], '37.7749');
      expect(ok.spoofAccepted(trusted, bus.trustedSenders), isFalse);
    });
  });

  group('webview_origin_confusion_ipc', () {
    test('remote origin misclassified as local runs privileged IPC; '
        'safe uses exact origin', () {
      final dispatcher = WebViewIpcDispatcher();
      const localOrigin = WebViewIpcDispatcher.defaultLocalOrigin;
      // A remote page whose host merely contains `localhost` as a subdomain.
      const remoteOrigin = 'https://tauri.localhost.evil.com';
      const command = WebViewIpcDispatcher.privilegedCommand;

      // The loose classifier itself misclassifies the remote origin as local.
      expect(dispatcher.classifier.isLocal(remoteOrigin), isTrue);
      expect(dispatcher.classifier.isLocalStrict(remoteOrigin), isFalse);

      // VULN: the remote page reaches the local-only privileged command.
      final vuln = dispatcher.dispatch(
        command: command,
        callerOrigin: remoteOrigin,
      );
      expect(vuln.executed, isTrue);
      expect(vuln.blocked, isFalse);
      expect(vuln.classifiedLocal, isTrue);
      expect(vuln.output, WebViewIpcDispatcher.privilegedOutput);
      expect(vuln.privilegedReachedRemote(remoteOrigin, localOrigin), isTrue);

      // SECURE: exact canonical-origin comparison rejects the remote page.
      final secure = dispatcher.dispatchSafe(
        command: command,
        callerOrigin: remoteOrigin,
      );
      expect(secure.executed, isFalse);
      expect(secure.blocked, isTrue);
      expect(secure.classifiedLocal, isFalse);
      expect(secure.output, isNull);
      expect(
        secure.privilegedReachedRemote(remoteOrigin, localOrigin),
        isFalse,
      );

      // SECURE also rejects another look-alike host that contains the token.
      final lookalike = dispatcher.dispatchSafe(
        command: command,
        callerOrigin: 'app://localhost.attacker.tld',
      );
      expect(lookalike.blocked, isTrue);

      // SECURE still serves the true local origin.
      final ok = dispatcher.dispatchSafe(
        command: command,
        callerOrigin: localOrigin,
      );
      expect(ok.executed, isTrue);
      expect(ok.output, WebViewIpcDispatcher.privilegedOutput);
      expect(ok.privilegedReachedRemote(localOrigin, localOrigin), isFalse);
    });
  });

  group('webview_js_injection_ssl_bypass', () {
    test('accept-all TLS loads MITM script and steals token; '
        'safe validates cert', () {
      const loader = WebViewLoader();

      // VULN: accept-all transport loads the MITM-rewritten page and its
      // injected script exfiltrates the token.
      final vuln = loader.load();
      expect(vuln.loaded, isTrue);
      expect(vuln.blocked, isFalse);
      expect(vuln.injectedScriptExecuted, isTrue);
      expect(vuln.exfiltratedToken, WebViewLoader.sessionToken);
      expect(vuln.tokenStolen, isTrue);

      // SECURE: cert-validating transport rejects the forged MITM cert; the
      // page never loads and no script can run.
      final secure = loader.loadSafe();
      expect(secure.loaded, isFalse);
      expect(secure.blocked, isTrue);
      expect(secure.injectedScriptExecuted, isFalse);
      expect(secure.exfiltratedToken, isNull);
      expect(secure.tokenStolen, isFalse);
      expect(secure.blockReason, isNotNull);
    });
  });
}
