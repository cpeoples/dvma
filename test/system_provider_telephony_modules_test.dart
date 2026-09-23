import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/system_provider/privileged_provider_activation_abuse/provider_activation_manager.dart';
import 'package:dvma/modules/system_provider/mediaprojection_screencapture_authorization_bypass/media_projection_broker.dart';
import 'package:dvma/modules/system_provider/custom_keyboard_input_interception/ime_keyboard.dart';
import 'package:dvma/modules/platform/telephony_capability_abuse/telephony_gateway.dart';
import 'package:dvma/modules/platform/document_picker_trusted_file_confusion/document_importer.dart';
import 'package:dvma/modules/platform/system_surface_privileged_appintent_exposure/app_intent_surface_router.dart';
import 'package:dvma/modules/auth/biometric_authorization_not_bound/biometric_authorizer.dart';
import 'package:dvma/modules/auth/credential_provider_release_authorization/credential_provider_service.dart';
import 'package:dvma/modules/native_bridge/webview_cleartext_mixed_content_downgrade/webview_transport_loader.dart';

/// Regression suite for the system-provider / telephony / picker / app-intent /
/// biometric / credential-provider / WebView-downgrade training modules. Each
/// test asserts the INSECURE path grants / records / exfiltrates / dials /
/// trusts / invokes / replays / releases / downgrades AND that the secure
/// contrast blocks it, so an accidental "fix" of the lab fails CI.
void main() {
  group('privileged_provider_activation_abuse', () {
    test('coerced enablement drives confused deputy; safe path refuses', () {
      const type = ProviderType.phoneAccount;

      // VULN: enablement toggle tapped through an overlay is still granted,
      // and the capability is driven for the untrusted attacker.
      final mgr = ProviderActivationManager();
      final enable = mgr.enable(type, obscuredByOverlay: true);
      expect(enable.enabled, isTrue);
      expect(enable.coerced, isTrue);
      expect(mgr.isEnabled(type), isTrue);

      final invoke = mgr.invoke(
        type,
        ProviderActivationManager.attackerPackage,
      );
      expect(invoke.performed, isTrue);
      expect(invoke.confusedDeputy, isTrue);

      // SECURE: obscured tap refused -> not enabled.
      final secureMgr = ProviderActivationManager();
      final secureEnable = secureMgr.enableSafe(type, obscuredByOverlay: true);
      expect(secureEnable.enabled, isFalse);
      expect(secureEnable.coerced, isFalse);
      expect(secureEnable.denyReason, contains('obscured'));

      final secureInvoke = secureMgr.invokeSafe(
        type,
        ProviderActivationManager.attackerPackage,
      );
      expect(secureInvoke.performed, isFalse);
      expect(secureInvoke.confusedDeputy, isFalse);
      expect(secureInvoke.denyReason, contains('genuine'));

      // SECURE: even a genuine enablement re-checks the caller on invoke.
      final genuineMgr = ProviderActivationManager();
      genuineMgr.enableSafe(type, obscuredByOverlay: false);
      final untrusted = genuineMgr.invokeSafe(
        type,
        ProviderActivationManager.attackerPackage,
      );
      expect(untrusted.performed, isFalse);
      expect(untrusted.denyReason, contains('not trusted'));

      final trusted = genuineMgr.invokeSafe(type, 'com.dvma.app');
      expect(trusted.performed, isTrue);
      expect(trusted.confusedDeputy, isFalse);
    });
  });

  group('mediaprojection_screencapture_authorization_bypass', () {
    test(
      'forwarded token records screen; safe path binds token to package',
      () {
        // VULN: token issued to the meeting app is forwarded to the attacker
        // recorder and starts capture.
        final broker = MediaProjectionBroker();
        final token = broker.issueToken(
          MediaProjectionBroker.consentingPackage,
        );
        final vuln = broker.startCapture(
          token,
          MediaProjectionBroker.attackerPackage,
        );
        expect(vuln.recording, isTrue);
        expect(vuln.unauthorized, isTrue);
        expect(vuln.grantedToPackage, MediaProjectionBroker.consentingPackage);

        // SECURE: token bound to consenting package -> forwarded use refused.
        final secureBroker = MediaProjectionBroker();
        final secureToken = secureBroker.issueToken(
          MediaProjectionBroker.consentingPackage,
        );
        final secure = secureBroker.startCaptureSafe(
          secureToken,
          MediaProjectionBroker.attackerPackage,
        );
        expect(secure.recording, isFalse);
        expect(secure.unauthorized, isFalse);
        expect(secure.denyReason, contains('bound to'));

        // SECURE: the consenting package may capture once (single-use).
        final ok = secureBroker.startCaptureSafe(
          secureToken,
          MediaProjectionBroker.consentingPackage,
        );
        expect(ok.recording, isTrue);
        final reuse = secureBroker.startCaptureSafe(
          secureToken,
          MediaProjectionBroker.consentingPackage,
        );
        expect(reuse.recording, isFalse);
        expect(reuse.denyReason, contains('single-use'));

        // SECURE: an expired token is refused.
        final expBroker = MediaProjectionBroker();
        final expToken = expBroker.issueToken(
          MediaProjectionBroker.consentingPackage,
          ttl: 1,
        );
        expBroker.advance(5);
        final expired = expBroker.startCaptureSafe(
          expToken,
          MediaProjectionBroker.consentingPackage,
        );
        expect(expired.recording, isFalse);
        expect(expired.denyReason, contains('expired'));
      },
    );
  });

  group('custom_keyboard_input_interception', () {
    test('secure field exfiltrated; safe path never logs/transmits it', () {
      // VULN: a network-enabled keyboard captures + exfiltrates the password.
      final kb = ImeKeyboard(hasNetworkAccess: true);
      final vuln = kb.onKey(ImeKeyboard.passwordField, ImeKeyboard.secret);
      expect(vuln.sensitiveLeaked, isTrue);
      expect(vuln.captured, ImeKeyboard.secret);
      expect(vuln.exfiltrated, ImeKeyboard.secret);
      expect(kb.exfilSink.join(), ImeKeyboard.secret);

      // SECURE: an isolated keyboard refuses to log/transmit secure fields.
      final secureKb = ImeKeyboard(hasNetworkAccess: false);
      final secure = secureKb.onKeySafe(
        ImeKeyboard.passwordField,
        ImeKeyboard.secret,
      );
      expect(secure.sensitiveLeaked, isFalse);
      expect(secure.captured, isEmpty);
      expect(secure.exfiltrated, isEmpty);
      expect(secureKb.keylog, isEmpty);
      expect(secureKb.exfilSink, isEmpty);

      // SECURE: a non-secure field is buffered locally but never exfiltrated.
      final search = secureKb.onKeySafe(ImeKeyboard.searchField, 'weather');
      expect(search.captured, 'weather');
      expect(search.exfiltrated, isEmpty);
      expect(secureKb.exfilSink, isEmpty);
    });
  });

  group('telephony_capability_abuse', () {
    test('untrusted caller dials premium number; safe path requires perm', () {
      const gateway = TelephonyGateway();
      const caller = TelephonyGateway.untrustedCaller;

      // VULN: no permission, but the call is placed anyway.
      final vuln = gateway.invoke(
        caller,
        TelephonyCapability.placeCall,
        TelephonyGateway.premiumNumber,
      );
      expect(vuln.performed, isTrue);
      expect(vuln.abused, isTrue);

      // SECURE: caller lacks CALL_PHONE -> refused.
      final secure = gateway.invokeSafe(
        caller,
        TelephonyCapability.placeCall,
        TelephonyGateway.premiumNumber,
      );
      expect(secure.performed, isFalse);
      expect(secure.abused, isFalse);
      expect(secure.denyReason, contains('lacks'));

      // SECURE: with the permission but no confirmation -> still refused.
      const permittedCaller = TelephonyCaller(
        package: 'com.dvma.app',
        heldPermissions: {'android.permission.CALL_PHONE'},
      );
      final noConfirm = gateway.invokeSafe(
        permittedCaller,
        TelephonyCapability.placeCall,
        '+1-555-0100',
      );
      expect(noConfirm.performed, isFalse);
      expect(noConfirm.denyReason, contains('confirmation'));

      // SECURE: permission + confirmation -> allowed.
      final ok = gateway.invokeSafe(
        permittedCaller,
        TelephonyCapability.placeCall,
        '+1-555-0100',
        userConfirmed: true,
      );
      expect(ok.performed, isTrue);
      expect(ok.abused, isFalse);
    });
  });

  group('document_picker_trusted_file_confusion', () {
    test('declared type/path trusted; safe path re-validates + confines', () {
      const importer = DocumentImporter();
      const doc = DocumentImporter.hostile;

      // VULN: trust the declared ".txt" claim -> executed as code, path
      // escapes the sandbox.
      final vuln = importer.import(doc);
      expect(vuln.imported, isTrue);
      expect(vuln.executedAsCode, isTrue);
      expect(vuln.escapedSandbox, isTrue);
      expect(vuln.trustedType, doc.declaredMimeType);
      expect(doc.sniffedType, isNot(doc.declaredMimeType));

      // SECURE: path escapes sandbox -> refused first.
      final secure = importer.importSafe(doc);
      expect(secure.imported, isFalse);
      expect(secure.blocked, isTrue);
      expect(secure.executedAsCode, isFalse);
      expect(secure.reason, contains('sandbox'));

      // SECURE: a type-mismatched but in-sandbox file is refused on content.
      const mismatch = PickedDocument(
        declaredName: 'notes.txt',
        declaredMimeType: 'text/plain',
        declaredPath: '/data/data/com.dvma/files/inbox/notes.txt',
        bytes: '#!/bin/sh\nid\n',
      );
      final mism = importer.importSafe(mismatch);
      expect(mism.imported, isFalse);
      expect(mism.blocked, isTrue);
      expect(mism.reason, contains('does not match'));

      // SECURE: a benign, self-consistent, in-sandbox document imports.
      final ok = importer.importSafe(DocumentImporter.benign);
      expect(ok.imported, isTrue);
      expect(ok.executedAsCode, isFalse);
      expect(ok.escapedSandbox, isFalse);
    });
  });

  group('system_surface_privileged_appintent_exposure', () {
    test(
      'any surface fires privileged intent; safe path enforces allowlist',
      () {
        const router = AppIntentSurfaceRouter();
        const intent = PrivilegedIntent.exportData;

        // VULN: a Control (lock-screen-reachable) fires "export data".
        final vuln = router.invokeFrom(IntentSurface.control, intent);
        expect(vuln.performed, isTrue);
        expect(vuln.unauthorizedSurface, isTrue);

        // SECURE: Control is not allowlisted for sensitive intents -> refused.
        final secure = router.invokeFromSafe(IntentSurface.control, intent);
        expect(secure.performed, isFalse);
        expect(secure.unauthorizedSurface, isFalse);
        expect(secure.denyReason, contains('not authorized'));

        // SECURE: an allowlisted surface still needs device authentication.
        final noAuth = router.invokeFromSafe(IntentSurface.siri, intent);
        expect(noAuth.performed, isFalse);
        expect(noAuth.denyReason, contains('authentication'));

        // SECURE: allowlisted surface + authenticated -> allowed.
        final ok = router.invokeFromSafe(
          IntentSurface.siri,
          intent,
          deviceAuthenticated: true,
        );
        expect(ok.performed, isTrue);
        expect(ok.unauthorizedSurface, isFalse);
      },
    );
  });

  group('biometric_authorization_not_bound', () {
    test('unbound success replayed onto another op; safe path binds it', () {
      final auth = BiometricAuthorizer();

      // VULN: a success for "view balance" is replayed onto the transfer.
      final vulnToken = auth.authorize(
        BiometricAuthorizer.operationView,
        promptSuccess: true,
      );
      final vuln = auth.useToken(
        BiometricAuthorizer.operationTransfer,
        vulnToken,
      );
      expect(vuln.authorized, isTrue);
      expect(vuln.replayed, isTrue);

      // SECURE: the token is signed for "view balance" only -> replay fails.
      final secureToken = auth.authorizeSafe(
        BiometricAuthorizer.operationView,
        promptSuccess: true,
      );
      final secure = auth.useTokenSafe(
        BiometricAuthorizer.operationTransfer,
        secureToken,
      );
      expect(secure.authorized, isFalse);
      expect(secure.replayed, isFalse);
      expect(secure.denyReason, contains('bound to'));

      // SECURE: the token authorizes the exact operation it was minted for.
      final ok = auth.useTokenSafe(
        BiometricAuthorizer.operationView,
        secureToken,
      );
      expect(ok.authorized, isTrue);

      // SECURE: a failed prompt yields no usable assertion.
      final failToken = auth.authorizeSafe(
        BiometricAuthorizer.operationView,
        promptSuccess: false,
      );
      final failed = auth.useTokenSafe(
        BiometricAuthorizer.operationView,
        failToken,
      );
      expect(failed.authorized, isFalse);
    });
  });

  group('credential_provider_release_authorization', () {
    test(
      'spoofed app extracts credential; safe path binds app + requires UV',
      () {
        final service = CredentialProviderService.seeded();

        // VULN: a spoofed calling app extracts the bank credential without UV.
        final vuln = service.getCredential(
          CredentialProviderService.bankRpId,
          CredentialProviderService.spoofedApp,
          userVerified: false,
        );
        expect(vuln.released, isTrue);
        expect(vuln.spoofedRelease, isTrue);
        expect(vuln.secret, isNotNull);

        // VULN: enumeration exposes every stored relying party.
        expect(
          service.enumerateRpIds(),
          contains(CredentialProviderService.bankRpId),
        );
        expect(service.enumerateRpIds().length, greaterThan(1));

        // SECURE: calling app not bound to rpId -> refused.
        final secure = service.getCredentialSafe(
          CredentialProviderService.bankRpId,
          CredentialProviderService.spoofedApp,
          userVerified: false,
        );
        expect(secure.released, isFalse);
        expect(secure.spoofedRelease, isFalse);
        expect(secure.denyReason, contains('not bound'));

        // SECURE: correct app but no UV -> refused.
        final noUv = service.getCredentialSafe(
          CredentialProviderService.bankRpId,
          CredentialProviderService.legitApp,
          userVerified: false,
        );
        expect(noUv.released, isFalse);
        expect(noUv.denyReason, contains('user verification'));

        // SECURE: correct app + UV -> released.
        final ok = service.getCredentialSafe(
          CredentialProviderService.bankRpId,
          CredentialProviderService.legitApp,
          userVerified: true,
        );
        expect(ok.released, isTrue);
        expect(ok.spoofedRelease, isFalse);
        expect(ok.secret, isNotNull);
      },
    );
  });

  group('webview_cleartext_mixed_content_downgrade', () {
    test(
      'cleartext/mixed content injects MITM script; safe path blocks it',
      () {
        const url = WebViewTransportLoader.httpUrl;

        // VULN: cleartext + mixed-content-always-allow -> MITM injection runs.
        final vuln = WebViewTransportLoader.insecure.load(url);
        expect(vuln.loaded, isTrue);
        expect(vuln.downgraded, isTrue);
        expect(vuln.injectedScriptExecuted, isTrue);
        expect(vuln.mitmInjected, isTrue);
        expect(vuln.exfiltratedToken, WebViewTransportLoader.sessionToken);

        // SECURE: cleartext blocked + mixed-content BLOCK -> http load refused.
        final secure = WebViewTransportLoader.secure.loadSafe(url);
        expect(secure.loaded, isFalse);
        expect(secure.blocked, isTrue);
        expect(secure.mitmInjected, isFalse);
        expect(secure.exfiltratedToken, isNull);
        expect(secure.reason, contains('refused'));

        // SECURE: an https-only URL still loads under the secure config.
        final https = WebViewTransportLoader.secure.loadSafe(
          'https://app.dvma.example/dashboard',
        );
        expect(https.loaded, isTrue);
        expect(https.blocked, isFalse);
      },
    );
  });
}
