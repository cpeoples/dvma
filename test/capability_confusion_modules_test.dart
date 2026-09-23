import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/platform/exported_component_state_manipulation/notification_center.dart';
import 'package:dvma/modules/platform/contentprovider_filename_path_traversal/file_import_provider.dart';
import 'package:dvma/modules/platform/app_intent_parameter_authorization/app_intent_router.dart';
import 'package:dvma/modules/privacy/notification_alternate_surface_disclosure/notification_surface_renderer.dart';

/// Regression suite for the capability-confusion / cross-boundary training
/// modules. Each test asserts the INSECURE path mutates / escapes / invokes /
/// leaks AND that the secure contrast blocks it, so an accidental "fix" of the
/// lab fails CI.
void main() {
  group('exported_component_state_manipulation', () {
    test('unowned caller cancels victim notif; safe path refuses', () {
      // VULN: attacker cancels the victim app's notification with no ownership
      // check.
      final vulnCenter = NotificationCenter.seeded();
      expect(
        vulnCenter.isActive(NotificationCenter.victimNotificationId),
        isTrue,
      );
      final vuln = vulnCenter.handleIntent(
        NotificationCenter.attackerPackage,
        NotificationCenter.victimNotificationId,
      );
      expect(vuln.mutated, isTrue);
      expect(vuln.crossOwnerMutation, isTrue);
      expect(vuln.targetOwner, NotificationCenter.victimPackage);
      expect(
        vulnCenter.isActive(NotificationCenter.victimNotificationId),
        isFalse,
      );

      // SECURE: same crafted intent refused; victim notif stays active.
      final secureCenter = NotificationCenter.seeded();
      final secure = secureCenter.handleIntentSafe(
        NotificationCenter.attackerPackage,
        NotificationCenter.victimNotificationId,
      );
      expect(secure.mutated, isFalse);
      expect(secure.crossOwnerMutation, isFalse);
      expect(secure.denyReason, isNotNull);
      expect(
        secureCenter.isActive(NotificationCenter.victimNotificationId),
        isTrue,
      );

      // SECURE: the owner may still cancel its OWN notification.
      final owner = NotificationCenter.seeded().handleIntentSafe(
        NotificationCenter.victimPackage,
        NotificationCenter.victimNotificationId,
      );
      expect(owner.mutated, isTrue);
      expect(owner.crossOwnerMutation, isFalse);

      // SECURE: a signature-permission holder is allowed too.
      final privileged = NotificationCenter.seeded().handleIntentSafe(
        NotificationCenter.attackerPackage,
        NotificationCenter.victimNotificationId,
        callerHoldsSignaturePermission: true,
      );
      expect(privileged.mutated, isTrue);
    });
  });

  group('contentprovider_filename_path_traversal', () {
    test(
      'traversal filename clobbers secrets; safe importer confines',
      () async {
        const bytes = '<map><string name="auth_token">ATTACKER</string></map>';

        // VULN: "../shared_prefs/secrets.xml" escapes the import dir and
        // overwrites the app's secrets.
        final vulnProvider = await FileImportProvider.seeded();
        expect(
          await vulnProvider.fileAt(FileImportProvider.secretsPath),
          FileImportProvider.originalSecrets,
        );
        final vuln = await vulnProvider.importFile(
          FileImportProvider.traversalDisplayName,
          bytes,
        );
        expect(vuln.wrote, isTrue);
        expect(vuln.escapedImportRoot(FileImportProvider.importRoot), isTrue);
        expect(vuln.resolvedPath, FileImportProvider.secretsPath);
        expect(
          await vulnProvider.fileAt(FileImportProvider.secretsPath),
          bytes,
        );

        // SECURE: same display name rejected; secrets untouched.
        final secureProvider = await FileImportProvider.seeded(tag: 'secure');
        final secure = await secureProvider.importFileSafe(
          FileImportProvider.traversalDisplayName,
          bytes,
        );
        expect(secure.wrote, isFalse);
        expect(secure.blocked, isTrue);
        expect(
          secure.escapedImportRoot(FileImportProvider.importRoot),
          isFalse,
        );
        expect(
          await secureProvider.fileAt(FileImportProvider.secretsPath),
          FileImportProvider.originalSecrets,
        );

        // SECURE: a benign display name still imports under the root.
        final okProvider = await FileImportProvider.seeded(tag: 'ok');
        final ok = await okProvider.importFileSafe(
          FileImportProvider.benignDisplayName,
          bytes,
        );
        expect(ok.wrote, isTrue);
        expect(ok.blocked, isFalse);
        expect(ok.escapedImportRoot(FileImportProvider.importRoot), isFalse);
        expect(
          ok.resolvedPath,
          '${FileImportProvider.importRoot}/'
          '${FileImportProvider.benignDisplayName}',
        );
      },
    );
  });

  group('app_intent_parameter_authorization', () {
    test('shortcut param exports victim account; safe path requires authz', () {
      const malicious = AppIntentInvocation(
        intentName: AppIntentRouter.exportIntent,
        params: {'accountId': AppIntentRouter.victimAccount},
      );

      // VULN: privileged export runs straight from the param, no authz.
      final vuln = AppIntentRouter.seeded().invoke(malicious);
      expect(vuln.executed, isTrue);
      expect(vuln.blocked, isFalse);
      expect(vuln.effect, contains(AppIntentRouter.victimAccount));

      // VULN: a crafted transfer likewise drains a foreign account.
      final router = AppIntentRouter.seeded();
      final drain = router.invoke(
        const AppIntentInvocation(
          intentName: AppIntentRouter.transferIntent,
          params: {
            'from': AppIntentRouter.victimAccount,
            'to': AppIntentRouter.ownAccount,
            'amount': '100000',
          },
        ),
      );
      expect(drain.executed, isTrue);
      expect(router.balanceOf(AppIntentRouter.victimAccount), 0);

      // SECURE: no token -> refused.
      final noToken = AppIntentRouter.seeded().invokeSafe(malicious);
      expect(noToken.executed, isFalse);
      expect(noToken.blocked, isTrue);
      expect(noToken.denyReason, contains('authorization token'));

      // SECURE: valid token but other-user account -> refused on ownership.
      final wrongOwner = AppIntentRouter.seeded().invokeSafe(
        const AppIntentInvocation(
          intentName: AppIntentRouter.exportIntent,
          params: {'accountId': AppIntentRouter.victimAccount},
          authToken: AppIntentRouter.validAuthToken,
        ),
      );
      expect(wrongOwner.executed, isFalse);
      expect(wrongOwner.blocked, isTrue);
      expect(wrongOwner.denyReason, contains('does not own'));

      // SECURE: authorized invocation on the caller's OWN account succeeds.
      final authorized = AppIntentRouter.seeded().invokeSafe(
        const AppIntentInvocation(
          intentName: AppIntentRouter.exportIntent,
          params: {'accountId': AppIntentRouter.ownAccount},
          authToken: AppIntentRouter.validAuthToken,
        ),
      );
      expect(authorized.executed, isTrue);
      expect(authorized.blocked, isFalse);
    });
  });

  group('notification_alternate_surface_disclosure', () {
    test('alt surface leaks full content; safe path redacts everywhere', () {
      const renderer = NotificationRenderer();
      const n = SensitiveNotification.sample;

      // VULN: lock screen redacts, but the alternate surface leaks the full
      // private content.
      final vulnLock = renderer.render(n, Surface.lockScreen);
      expect(vulnLock.leakedPrivate, isFalse);
      expect(vulnLock.displayed, n.publicContent);

      final vulnAlt = renderer.render(n, Surface.alternateSurface);
      expect(vulnAlt.leakedPrivate, isTrue);
      expect(vulnAlt.displayed, n.privateContent);
      expect(vulnAlt.displayed, contains('HIV test result'));

      // SECURE: the same redaction policy applies on the alternate surface.
      final safeAlt = renderer.renderSafe(n, Surface.alternateSurface);
      expect(safeAlt.leakedPrivate, isFalse);
      expect(safeAlt.displayed, n.publicContent);
      expect(safeAlt.displayed, isNot(contains('HIV test result')));

      final safeLock = renderer.renderSafe(n, Surface.lockScreen);
      expect(safeLock.displayed, n.publicContent);

      // SECURE: an AUTHENTICATED surface may show the full content.
      final authed = renderer.renderSafe(
        n,
        Surface.alternateSurface,
        authenticated: true,
      );
      expect(authed.displayed, n.privateContent);
      expect(authed.leakedPrivate, isFalse);
    });
  });
}
