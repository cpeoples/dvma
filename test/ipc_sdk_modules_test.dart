import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/platform/implicit_intent_sensitive_data/implicit_intent_bus.dart';
import 'package:dvma/modules/platform/pendingintent_provenance_confusion/pending_intent_authenticator.dart';
import 'package:dvma/modules/platform/inapp_browser_ui_spoofing/inapp_browser_model.dart';
import 'package:dvma/modules/supply_chain/sdk_exported_component_redirection/vulnerable_sdk_component.dart';

/// Regression suite for the IPC / bundled-SDK training modules. Each test
/// asserts the *insecure* behavior is still present (so an accidental "fix"
/// fails CI) AND that the secure contrast blocks the attack.
void main() {
  group('implicit_intent_sensitive_data', () {
    test(
      'implicit broadcast leaks to the eavesdropper, explicit send does not',
      () {
        const action = 'com.dvma.action.SHARE_SESSION';
        const extras = {
          'auth_token': 'eyJhbGciOiJIUzI1NiJ9.session-tok-9f3a',
          'account_email': 'victim@example.com',
        };
        final bus = ImplicitIntentBus.withEavesdropper();

        // VULN: the implicit broadcast reaches the malicious eavesdropper too.
        final vuln = bus.broadcastImplicit(action, extras);
        final packages = vuln.map((d) => d.packageName).toList();
        expect(packages, contains('com.evil.eavesdropper'));
        final eaves = vuln.firstWhere(
          (d) => d.packageName == 'com.evil.eavesdropper',
        );
        expect(eaves.trusted, isFalse);
        // The full sensitive payload was delivered to the attacker.
        expect(
          eaves.receivedExtras['auth_token'],
          'eyJhbGciOiJIUzI1NiJ9.session-tok-9f3a',
        );
        expect(eaves.receivedExtras['account_email'], 'victim@example.com');

        // SECURE: explicit send addressed to the trusted package only.
        final secure = bus.sendExplicit('com.dvma.app', action, extras);
        final securePackages = secure.map((d) => d.packageName).toList();
        expect(securePackages, contains('com.dvma.app'));
        expect(securePackages, isNot(contains('com.evil.eavesdropper')));
      },
    );
  });

  group('pendingintent_provenance_confusion', () {
    test(
      'vulnerable auth trusts the token claim, strict verifies the presenter',
      () {
        const token = PendingIntentToken(creatorPackage: 'com.trusted.app');
        const presenter = 'com.evil.app';

        // VULN: the evil presenter is authenticated AS the trusted creator.
        final vuln = PendingIntentAuthenticator.authenticate(token, presenter);
        expect(vuln.authenticated, isTrue);
        expect(vuln.identity, 'com.trusted.app');
        expect(vuln.spoofed, isTrue);

        // SECURE: the presenter/creator mismatch is rejected.
        final secure = PendingIntentAuthenticator.authenticateStrict(
          token,
          presenter,
        );
        expect(secure.authenticated, isFalse);
        expect(secure.identity, isNull);

        // SECURE still authenticates the genuine creator with a fresh,
        // non-replayable token.
        const goodToken = PendingIntentToken(
          creatorPackage: 'com.trusted.app',
          mutable: false,
        );
        final ok = PendingIntentAuthenticator.authenticateStrict(
          goodToken,
          'com.trusted.app',
        );
        expect(ok.authenticated, isTrue);
        expect(ok.identity, 'com.trusted.app');
      },
    );
  });

  group('sdk_exported_component_redirection', () {
    test('vulnerable SDK component redirects to private target, safe rejects', () {
      final intent = <String, Object?>{
        'forward': {'target': 'AccountCredentialsProvider'},
      };

      // VULN: the bundled SDK redirects to a private component and leaks data.
      final vuln = VulnerableSdkComponent.handleForwardedIntent(intent);
      expect(vuln.redirected, isTrue);
      expect(vuln.target, 'AccountCredentialsProvider');
      expect(vuln.leakedData, isNotNull);
      expect(vuln.leakedData, contains('password=Sup3rSecret!'));

      // SECURE: the private/external target is refused (not on the SDK's
      // allowlist), so nothing leaks.
      final secure = VulnerableSdkComponent.handleForwardedIntentSafe(intent);
      expect(secure.redirected, isFalse);
      expect(secure.leakedData, isNull);

      // SECURE still forwards to the SDK's own public endpoint.
      final ok = VulnerableSdkComponent.handleForwardedIntentSafe(
        <String, Object?>{
          'forward': {'target': 'EngageLabDeepLinkHandler'},
        },
      );
      expect(ok.redirected, isTrue);
    });
  });

  group('inapp_browser_ui_spoofing', () {
    test(
      'vulnerable address bar shows a spoofed origin, safe shows the real one',
      () {
        const page = BrowserPage(
          committedUrl: 'https://evil.example/login',
          claimedOrigin: 'https://bank.example',
        );

        // VULN: the address bar shows the attacker-claimed trusted origin.
        final vuln = InAppBrowserModel.displayedAddressBar(page);
        expect(vuln.shown, 'https://bank.example');
        expect(vuln.actual, 'https://evil.example');
        expect(vuln.shown, isNot(equals(vuln.actual)));
        expect(vuln.spoofed, isTrue);

        // SECURE: the address bar always reflects the real committed origin.
        final secure = InAppBrowserModel.displayedAddressBarSafe(page);
        expect(secure.shown, 'https://evil.example');
        expect(secure.shown, equals(secure.actual));
        expect(secure.spoofed, isFalse);
      },
    );
  });
}
