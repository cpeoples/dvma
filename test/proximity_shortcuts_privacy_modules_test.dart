import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/platform/proximity_transfer_unsafe_parsing/proximity_parser.dart';
import 'package:dvma/modules/platform/shortcuts_path_symlink_sandbox_escape/sandbox_fs.dart';
import 'package:dvma/modules/native_bridge/webview_sop_csp_disabled/webview_engine.dart';
import 'package:dvma/modules/native_bridge/shared_webview_miniapp_isolation/shared_webview_host.dart';
import 'package:dvma/modules/privacy/installed_app_enumeration/device_probe.dart';
import 'package:dvma/modules/privacy/cross_app_browser_history_access/history_store.dart';
import 'package:dvma/modules/platform/predictive_back_leakage/recents_snapshot.dart';
import 'package:dvma/modules/platform/photo_picker_over_access/photo_access.dart';

/// Regression suite for the proximity / shortcuts / WebView / privacy training
/// modules. Each test asserts the INSECURE path exhausts / escapes / leaks /
/// fingerprints AND that the secure contrast blocks it, so an accidental "fix"
/// of the lab fails CI.
void main() {
  group('proximity_transfer_unsafe_parsing', () {
    test('unbounded parse expands the bomb; safe parser rejects it', () {
      final parser = ProximityParser();
      const bomb = TransferPayload.billionLaughs;

      // VULN: unbounded parse materializes an astronomical node count.
      final vuln = parser.parse(bomb);
      expect(vuln.parsed, isTrue);
      expect(vuln.blocked, isFalse);
      // 10 references * 10^7 = 10^8 nodes, at/past the exhaustion threshold.
      expect(vuln.expandedNodes, 100000000);
      expect(vuln.exhausted(ProximityParser.exhaustionThreshold), isTrue);

      // SECURE: the bounded parser aborts before the bomb expands.
      final secure = parser.parseSafe(bomb);
      expect(secure.parsed, isFalse);
      expect(secure.blocked, isTrue);
      expect(secure.exhausted(ProximityParser.exhaustionThreshold), isFalse);
      expect(
        secure.expandedNodes,
        lessThanOrEqualTo(ProximityParser.maxEntityExpansion * 10),
      );
      expect(secure.reason, contains('entity expansion'));

      // SECURE also rejects a malformed payload outright...
      const malformed = TransferPayload(
        name: 'broken.plist',
        declaredBytes: 64,
        entityDefinitions: [],
        rootReferences: 1,
        malformed: true,
      );
      expect(parser.parseSafe(malformed).blocked, isTrue);

      // ...and an oversized payload.
      const huge = TransferPayload(
        name: 'huge.bin',
        declaredBytes: (1 << 20) + 1,
        entityDefinitions: [],
        rootReferences: 1,
      );
      expect(parser.parseSafe(huge).blocked, isTrue);

      // SECURE still parses a benign, well-formed payload.
      final ok = parser.parseSafe(TransferPayload.benign);
      expect(ok.parsed, isTrue);
      expect(ok.blocked, isFalse);
    });
  });

  group('shortcuts_path_symlink_sandbox_escape', () {
    test(
      'traversal + symlink escape the sandbox; safe resolver confines',
      () async {
        final fs = SandboxFs();

        // VULN: a ../ traversal reaches an out-of-container secret.
        final trav = await fs.resolve(SandboxFs.traversalInput);
        expect(trav.read, isTrue);
        expect(trav.blocked, isFalse);
        expect(trav.escapedSandbox(SandboxFs.containerRoot), isTrue);
        expect(trav.realPath, startsWith('/private/var/'));
        expect(trav.contents, contains('OUTSIDE SANDBOX'));

        // VULN: a planted symlink likewise escapes the container.
        final sym = await fs.resolve(SandboxFs.symlinkInput);
        expect(sym.escapedSandbox(SandboxFs.containerRoot), isTrue);
        expect(sym.contents, contains('OUTSIDE SANDBOX'));

        // SECURE: both escapes are rejected after canonicalization.
        final safeTrav = await fs.resolveSafe(SandboxFs.traversalInput);
        expect(safeTrav.read, isFalse);
        expect(safeTrav.blocked, isTrue);
        expect(safeTrav.escapedSandbox(SandboxFs.containerRoot), isFalse);

        final safeSym = await fs.resolveSafe(SandboxFs.symlinkInput);
        expect(safeSym.blocked, isTrue);
        expect(safeSym.escapedSandbox(SandboxFs.containerRoot), isFalse);

        // SECURE still serves a benign in-container request.
        final ok = await fs.resolveSafe(SandboxFs.benignInput);
        expect(ok.read, isTrue);
        expect(ok.escapedSandbox(SandboxFs.containerRoot), isFalse);
        expect(ok.contents, 'grocery list');
      },
    );
  });

  group('webview_sop_csp_disabled', () {
    test('insecure config steals cross-origin token; secure config blocks', () {
      const engine = WebViewEngine();

      // VULN: SOP + CSP disabled -> cross-origin read + inline script -> token.
      final vuln = engine.load(WebViewConfig.insecure);
      expect(vuln.crossOriginRead, isTrue);
      expect(vuln.inlineScriptExecuted, isTrue);
      expect(vuln.blocked, isFalse);
      expect(vuln.exfiltratedToken, WebViewEngine.sessionToken);
      expect(vuln.tokenStolen, isTrue);

      // SECURE: SOP enforced + restrictive CSP -> both blocked, no token.
      final secure = engine.load(WebViewConfig.secure);
      expect(secure.crossOriginRead, isFalse);
      expect(secure.inlineScriptExecuted, isFalse);
      expect(secure.blocked, isTrue);
      expect(secure.exfiltratedToken, isNull);
      expect(secure.tokenStolen, isFalse);
      expect(secure.reason, isNotNull);

      // Config-level assertions on the SOP/CSP flags themselves.
      expect(WebViewConfig.insecure.inlineScriptAllowed, isTrue);
      expect(
        WebViewConfig.insecure.allowsCrossOriginRead(WebViewEngine.crossOrigin),
        isTrue,
      );
      expect(WebViewConfig.secure.inlineScriptAllowed, isFalse);
      expect(
        WebViewConfig.secure.allowsCrossOriginRead(WebViewEngine.crossOrigin),
        isFalse,
      );
    });
  });

  group('shared_webview_miniapp_isolation', () {
    test('shared jar leaks B\'s cookie to A; partition blocks it', () {
      // VULN: single shared jar -> A reads B's cookie.
      final vulnHost = SharedWebViewHost();
      vulnHost.storeCookie(
        origin: SharedWebViewHost.miniAppB,
        name: SharedWebViewHost.cookieName,
        value: SharedWebViewHost.miniBCookie,
        partitioned: false,
      );
      final leak = vulnHost.readCookie(
        readerOrigin: SharedWebViewHost.miniAppA,
        name: SharedWebViewHost.cookieName,
      );
      expect(leak.granted, isTrue);
      expect(leak.value, SharedWebViewHost.miniBCookie);
      expect(
        leak.crossTenantLeak(
          SharedWebViewHost.miniAppA,
          SharedWebViewHost.miniAppB,
        ),
        isTrue,
      );

      // SECURE: per-origin partitions -> A cannot read B's cookie.
      final safeHost = SharedWebViewHost();
      safeHost.storeCookie(
        origin: SharedWebViewHost.miniAppB,
        name: SharedWebViewHost.cookieName,
        value: SharedWebViewHost.miniBCookie,
        partitioned: true,
      );
      final blocked = safeHost.readCookieSafe(
        readerOrigin: SharedWebViewHost.miniAppA,
        name: SharedWebViewHost.cookieName,
      );
      expect(blocked.granted, isFalse);
      expect(blocked.blocked, isTrue);
      expect(blocked.value, isNull);
      expect(
        blocked.crossTenantLeak(
          SharedWebViewHost.miniAppA,
          SharedWebViewHost.miniAppB,
        ),
        isFalse,
      );

      // SECURE: B still reads its own cookie from its partition.
      final own = safeHost.readCookieSafe(
        readerOrigin: SharedWebViewHost.miniAppB,
        name: SharedWebViewHost.cookieName,
      );
      expect(own.granted, isTrue);
      expect(own.value, SharedWebViewHost.miniBCookie);
    });
  });

  group('installed_app_enumeration', () {
    test('full probe builds a fingerprint; scoped check does not', () {
      final probe = DeviceProbe();

      // VULN: probing the whole list returns a broad fingerprint.
      final vuln = probe.enumerate(DeviceProbe.candidates);
      expect(vuln.isFingerprint, isTrue);
      expect(vuln.detected.length, greaterThan(1));
      expect(vuln.probedCount, DeviceProbe.candidates.length);
      // Sensitive categories are disclosed.
      final schemes = vuln.detected.map((c) => c.scheme).toSet();
      expect(schemes.contains('grindr'), isTrue);
      expect(schemes.contains('mychart'), isTrue);
      expect(vuln.fingerprint, contains('grindr'));

      // SECURE: only the declared scheme is checked -> no fingerprint.
      final secure = probe.enumerateSafe();
      expect(secure.isFingerprint, isFalse);
      expect(secure.probedCount, 1);
      expect(secure.detected.length, lessThanOrEqualTo(1));
      final secureSchemes = secure.detected.map((c) => c.scheme).toSet();
      expect(secureSchemes.contains('grindr'), isFalse);
      expect(secureSchemes.contains('mychart'), isFalse);
      // Only the needed scheme may appear.
      for (final s in secureSchemes) {
        expect(s, DeviceProbe.neededScheme);
      }
    });
  });

  group('cross_app_browser_history_access', () {
    test(
      'world-readable read leaks history; safe requires consent + scope',
      () {
        final store = HistoryStore();

        // VULN: read the other app's history directly, no consent.
        final vuln = store.read();
        expect(vuln.granted, isTrue);
        expect(vuln.blocked, isFalse);
        expect(vuln.historyLeaked, isTrue);
        expect(vuln.entries, isNotEmpty);
        expect(
          vuln.entries.map((e) => e.url).join(),
          contains('clinic.example'),
        );

        // SECURE: no consent -> nothing returned.
        final denied = store.readSafe(consentGranted: false);
        expect(denied.granted, isFalse);
        expect(denied.blocked, isTrue);
        expect(denied.historyLeaked, isFalse);
        expect(denied.entries, isEmpty);

        // SECURE: even with consent the API is scoped -> other app's private
        // history is never dumped.
        final consented = store.readSafe(consentGranted: true);
        expect(consented.historyLeaked, isFalse);
        expect(consented.entries, isEmpty);
      },
    );
  });

  group('predictive_back_leakage', () {
    test('recents snapshot captures the secret when not marked secure', () {
      const secret = 'Recovery key: DVMA{r3c3nts_snapsh0t_l3ak}';
      expect(RecentsSnapshotSimulator.snapshotLeaks(secret), isTrue);
      // FLAG_SECURE would obscure it.
      expect(
        RecentsSnapshotSimulator.snapshotLeaks(secret, flagSecure: true),
        isFalse,
      );
    });
  });

  group('photo_picker_over_access', () {
    test('full-library request over-collects vs the scoped picker', () {
      final full = PhotoAccess.requestFullLibraryAccess();
      expect(full.overCollects, isTrue);
      expect(full.standingPermission, isTrue);
      expect(full.grantedItems.length, PhotoAccess.deviceLibrary.length);

      final scoped = PhotoAccess.scopedPicker(const ['IMG_0002.jpg']);
      expect(scoped.overCollects, isFalse);
      expect(scoped.standingPermission, isFalse);
      expect(scoped.grantedItems, ['IMG_0002.jpg']);
    });
  });
}
