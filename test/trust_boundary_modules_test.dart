import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/platform/deeplink_to_webview_navigation/deeplink_webview_router.dart';
import 'package:dvma/modules/platform/exported_component_arbitrary_url_activity/exported_launcher.dart';
import 'package:dvma/modules/auth/deeplink_authentication_bypass/deeplink_auth_router.dart';
import 'package:dvma/modules/input_validation/deeplink_regex_dos/redos_link_parser.dart';
import 'package:dvma/modules/supply_chain/dependency_confusion/dependency_resolver.dart';

/// Regression suite for the trust-boundary training modules. Each test asserts
/// the *insecure* behavior is still present (so an accidental "fix" fails CI)
/// AND that the secure contrast blocks the attack.
void main() {
  group('deeplink_to_webview_navigation', () {
    test('vulnerable router loads the attacker origin, safe rejects it', () {
      const evil = 'dvma://open?url=https://evil.example/phish';

      // VULN: the url param is loaded verbatim into the trusted WebView.
      final vuln = DeeplinkWebViewRouter.resolveWebViewUrl(evil);
      expect(vuln, 'https://evil.example/phish');

      // Even dangerous schemes pass through unchecked.
      expect(
        DeeplinkWebViewRouter.resolveWebViewUrl(
          'dvma://open?url=javascript:alert(1)',
        ),
        'javascript:alert(1)',
      );

      // SECURE: only first-party https origins are allowed.
      final safe = DeeplinkWebViewRouter.resolveWebViewUrlSafe(evil);
      expect(safe.allowed, isFalse);
      expect(safe.url, isNull);

      // SECURE still allows a first-party origin.
      final ok = DeeplinkWebViewRouter.resolveWebViewUrlSafe(
        'dvma://open?url=https://app.dvma.example/home',
      );
      expect(ok.allowed, isTrue);
      expect(ok.url, 'https://app.dvma.example/home');
    });
  });

  group('exported_component_arbitrary_url_activity', () {
    test(
      'vulnerable handler opens arbitrary URL/internal activity, safe rejects',
      () {
        // VULN: an internal/privileged activity is opened with app privileges.
        final act = ExportedLauncher.handleExternalIntent({
          'activity': 'InternalAdminActivity',
        });
        expect(act.opened, isTrue);
        expect(act.privileged, isTrue);
        expect(act.target, 'InternalAdminActivity');

        // VULN: an arbitrary attacker URL is opened.
        final url = ExportedLauncher.handleExternalIntent({
          'target': 'https://evil.example/attacker',
        });
        expect(url.opened, isTrue);
        expect(url.target, 'https://evil.example/attacker');

        // SECURE: internal activity rejected.
        final secureAct = ExportedLauncher.handleExternalIntentSafe({
          'activity': 'InternalAdminActivity',
        });
        expect(secureAct.opened, isFalse);

        // SECURE: arbitrary URL rejected.
        final secureUrl = ExportedLauncher.handleExternalIntentSafe({
          'target': 'https://evil.example/attacker',
        });
        expect(secureUrl.opened, isFalse);

        // SECURE still allows a public activity + first-party URL.
        expect(
          ExportedLauncher.handleExternalIntentSafe({
            'activity': 'MainActivity',
          }).opened,
          isTrue,
        );
        expect(
          ExportedLauncher.handleExternalIntentSafe({
            'target': 'https://app.dvma.example/x',
          }).opened,
          isTrue,
        );
      },
    );
  });

  group('deeplink_authentication_bypass', () {
    test('vulnerable router opens wallet while logged out, safe redirects', () {
      final loggedOut = DeeplinkAuthRouter(isAuthenticated: false);

      // VULN: the protected wallet route opens and serves its balance with no
      // auth check.
      final vuln = DeeplinkAuthRouter.navigate(loggedOut, 'dvma://wallet');
      expect(vuln.screen, '/wallet');
      expect(vuln.redirectedToLogin, isFalse);
      expect(vuln.content, contains('WALLET BALANCE'));

      // SECURE: logged out -> redirect to login, no sensitive content.
      final secure = DeeplinkAuthRouter.navigateSafe(
        loggedOut,
        'dvma://wallet',
      );
      expect(secure.redirectedToLogin, isTrue);
      expect(secure.screen, '/login');
      expect(secure.content, isNull);

      // SECURE: once authenticated, the wallet is served.
      final loggedIn = DeeplinkAuthRouter(isAuthenticated: true);
      final ok = DeeplinkAuthRouter.navigateSafe(loggedIn, 'dvma://wallet');
      expect(ok.redirectedToLogin, isFalse);
      expect(ok.content, contains('WALLET BALANCE'));
    });
  });

  group('deeplink_regex_dos', () {
    test('vulnerable cost grows super-linearly / hangs, safe stays linear', () {
      // Crafted input: run of 'a' then a non-matching char -> exponential.
      final crafted = '${'a' * 40}!';

      final steps20 = RedosLinkParser.measureBacktracking('${'a' * 20}!');
      final steps30 = RedosLinkParser.measureBacktracking('${'a' * 30}!');

      // Super-linear: +10 chars multiplies the step count by ~2^10 (>1000x),
      // far more than any linear growth.
      expect(steps30, greaterThan(steps20 * 1000));

      // VULN: the crafted link would hang the vulnerable parser.
      expect(RedosLinkParser.wouldHang(crafted), isTrue);
      final vuln = RedosLinkParser.parse('dvma://open/$crafted');
      expect(vuln.hangs, isTrue);
      expect(vuln.steps, greaterThan(1000000));

      // SECURE: the linear parser stays cheap and never hangs.
      final safe = RedosLinkParser.parseSafe('dvma://open/$crafted');
      expect(safe.hangs, isFalse);
      // Linear cost is bounded by input length -> nowhere near the hang bar.
      expect(safe.steps, lessThan(1000));
      expect(
        RedosLinkParser.parseSafe('dvma://open/${'a' * 100}').hangs,
        isFalse,
      );
    });
  });

  group('dependency_confusion', () {
    test(
      'vulnerable resolver selects the public impostor, scoped pins private',
      () {
        // VULN: the internal name resolves to the attacker's higher public
        // version.
        final vuln = DependencyResolver.resolve('acme-internal-auth');
        expect(vuln.isImpostor, isTrue);
        expect(vuln.version, '9.9.9');
        expect(vuln.source, 'public-registry');

        // SECURE: scoped resolution pins to the trusted private package.
        final secure = DependencyResolver.resolveScoped('acme-internal-auth');
        expect(secure.isImpostor, isFalse);
        expect(secure.version, '1.2.0');
        expect(secure.source, 'private-registry');

        // SECURE still resolves genuine public packages from public.
        final pub = DependencyResolver.resolveScoped('left-pad');
        expect(pub.version, '1.3.0');
        expect(pub.source, 'public-registry');
      },
    );
  });
}
