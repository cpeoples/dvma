import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/storage/keychain_state_integrity_manipulation/keychain_store.dart';
import 'package:dvma/modules/storage/keychain_access_group_authorization_confusion/keychain_service.dart';
import 'package:dvma/modules/platform/clipboard_unauthorized_write_integrity/clipboard_writer.dart';
import 'package:dvma/modules/platform/clipboard_to_privileged_action_injection/privileged_action_handler.dart';
import 'package:dvma/modules/platform/authorization_by_mutable_resource_state/media_request_broker.dart';
import 'package:dvma/modules/privacy/assistant_locked_device_capability_abuse/assistant_gateway.dart';
import 'package:dvma/modules/input_validation/protected_data_access_via_input_validation/resource_authorizer.dart';
import 'package:dvma/modules/native_bridge/provider_metadata_to_filesystem_traversal/file_picker_plugin.dart';

/// Regression suite for the keychain-integrity / keychain-authz / clipboard /
/// mutable-state / locked-assistant / input-validation / provider-traversal
/// training modules. Each test asserts the INSECURE path tampers / reads
/// cross-group / overwrites / injects / grants / leaks-while-locked / bypasses
/// authz / traverses AND that the secure contrast blocks it, so an accidental
/// "fix" of the lab fails CI.
void main() {
  group('keychain_state_integrity_manipulation', () {
    test('tampered item trusted; safe path verifies MAC and rejects', () {
      // VULN: a local attacker rewrites the entitlement blob to admin WITHOUT
      // the app MAC key; the app trusts it and escalates.
      final store = KeychainStore.seeded()
        ..attackerModify(
          KeychainStore.entitlementKey,
          KeychainStore.forgedValue,
        );
      final vuln = store.readTrusted(KeychainStore.entitlementKey);
      expect(vuln.privilegeGranted, isTrue);
      expect(vuln.integrityVerified, isFalse);
      expect(vuln.tampered, isTrue);
      expect(vuln.storedValue, contains('role=admin'));

      // SECURE: the MAC over the stored value no longer matches -> rejected.
      final secure = store.readVerified(KeychainStore.entitlementKey);
      expect(secure.privilegeGranted, isFalse);
      expect(secure.integrityVerified, isFalse);
      expect(secure.tampered, isFalse);
      expect(secure.reason, contains('integrity tag mismatch'));

      // SECURE: an untampered, genuine item verifies and is acted on.
      final genuine = KeychainStore.seeded().readVerified(
        KeychainStore.entitlementKey,
      );
      expect(genuine.integrityVerified, isTrue);
      expect(genuine.privilegeGranted, isFalse); // genuine value is non-admin
      expect(genuine.storedValue, KeychainStore.genuineValue);
    });
  });

  group('keychain_access_group_authorization_confusion', () {
    test('wildcard group read cross-app; safe path requires exact group', () {
      // VULN: attacker-group caller reads an item stored under a wildcard
      // group.
      final vuln = KeychainService.seeded().read(
        KeychainService.attackerGroup,
        KeychainService.secretKey,
      );
      expect(vuln.granted, isTrue);
      expect(vuln.crossGroupLeak, isTrue);
      expect(vuln.value, KeychainService.secretValue);
      expect(vuln.itemAccessGroup, KeychainService.wildcardGroup);

      // SECURE: over-broad stored group refused for a mismatched caller.
      final secure = KeychainService.seeded().readScoped(
        KeychainService.attackerGroup,
        KeychainService.secretKey,
      );
      expect(secure.granted, isFalse);
      expect(secure.crossGroupLeak, isFalse);
      expect(secure.value, isNull);
      expect(secure.denyReason, contains('over-broad group'));

      // SECURE: a properly-scoped item is served to its exact app group.
      final ok = KeychainService.seeded().readScoped(
        KeychainService.appPrivateGroup,
        'public_pref',
      );
      expect(ok.granted, isTrue);
      expect(ok.crossGroupLeak, isFalse);
      expect(ok.value, 'theme=dark');
    });
  });

  group('clipboard_unauthorized_write_integrity', () {
    test('untrusted origin overwrites clipboard; safe path refuses', () {
      // VULN: a hostile WebView origin overwrites the user's copied address
      // with no gesture.
      final clip = SystemClipboard(ClipboardWriter.userAddress);
      final vuln = ClipboardWriter(clip).writeFromContent(
        ClipboardWriter.untrustedOrigin,
        ClipboardWriter.attackerAddress,
      );
      expect(vuln.wrote, isTrue);
      expect(vuln.tampered, isTrue);
      expect(vuln.clipboardAfter, ClipboardWriter.attackerAddress);
      expect(clip.value, ClipboardWriter.attackerAddress);

      // SECURE: untrusted origin without a gesture -> refused; user value kept.
      final clip2 = SystemClipboard(ClipboardWriter.userAddress);
      final secure = ClipboardWriter(clip2).writeFromContentSafe(
        ClipboardWriter.untrustedOrigin,
        ClipboardWriter.attackerAddress,
      );
      expect(secure.wrote, isFalse);
      expect(secure.tampered, isFalse);
      expect(secure.denyReason, contains('untrusted origin'));
      expect(clip2.value, ClipboardWriter.userAddress);

      // SECURE: trusted origin WITHOUT a gesture is still refused.
      final clip3 = SystemClipboard(ClipboardWriter.userAddress);
      final noGesture = ClipboardWriter(clip3).writeFromContentSafe(
        ClipboardWriter.trustedOrigin,
        ClipboardWriter.userAddress,
      );
      expect(noGesture.wrote, isFalse);
      expect(noGesture.denyReason, contains('user gesture'));

      // SECURE: trusted origin WITH a valid gesture is allowed.
      final clip4 = SystemClipboard('');
      final ok = ClipboardWriter(clip4).writeFromContentSafe(
        ClipboardWriter.trustedOrigin,
        ClipboardWriter.userAddress,
        gestureToken: ClipboardWriter.validGestureToken,
      );
      expect(ok.wrote, isTrue);
      expect(clip4.value, ClipboardWriter.userAddress);
    });
  });

  group('clipboard_to_privileged_action_injection', () {
    test(
      'tainted clipboard drives payment; safe path validates + confirms',
      () {
        const tainted = ClipboardEntry(
          value: PrivilegedActionHandler.injectedPayee,
          origin: PrivilegedActionHandler.untrustedOrigin,
        );

        // VULN: tainted clipboard content flows straight into the payment.
        final vuln = const PrivilegedActionHandler().runFromClipboard(tainted);
        expect(vuln.executed, isTrue);
        expect(vuln.injectedFromUntrusted, isTrue);
        expect(vuln.payload, contains('EVIL-DRAIN-999'));

        // SECURE: untrusted origin -> refused before any payment.
        final secure = const PrivilegedActionHandler().runFromClipboardSafe(
          tainted,
        );
        expect(secure.executed, isFalse);
        expect(secure.injectedFromUntrusted, isFalse);
        expect(secure.denyReason, contains('untrusted origin'));

        // SECURE: trusted origin but non-allowlisted payee -> refused.
        const trustedBadPayee = ClipboardEntry(
          value: 'pay to acct:EVIL-DRAIN-999 amount:1.00',
          origin: PrivilegedActionHandler.trustedOrigin,
        );
        final badPayee = const PrivilegedActionHandler().runFromClipboardSafe(
          trustedBadPayee,
          userConfirmed: true,
        );
        expect(badPayee.executed, isFalse);
        expect(badPayee.denyReason, contains('allowlist'));

        // SECURE: trusted + allowlisted but no confirmation -> refused.
        const trustedGood = ClipboardEntry(
          value: PrivilegedActionHandler.legitPayee,
          origin: PrivilegedActionHandler.trustedOrigin,
        );
        final noConfirm = const PrivilegedActionHandler().runFromClipboardSafe(
          trustedGood,
        );
        expect(noConfirm.executed, isFalse);
        expect(noConfirm.denyReason, contains('confirmation'));

        // SECURE: trusted + allowlisted + confirmed -> allowed.
        final ok = const PrivilegedActionHandler().runFromClipboardSafe(
          trustedGood,
          userConfirmed: true,
        );
        expect(ok.executed, isTrue);
        expect(ok.injectedFromUntrusted, isFalse);
      },
    );
  });

  group('authorization_by_mutable_resource_state', () {
    test('existence check grants reserved path; safe path binds owner', () {
      // VULN: attacker claims a path the victim reserved but has not written.
      final vuln = MediaRequestBroker.seeded().createRequest(
        MediaRequestBroker.attacker,
        MediaRequestBroker.contestedPath,
      );
      expect(vuln.granted, isTrue);
      expect(vuln.stolenFromOwner, isTrue);
      expect(vuln.effectiveOwner, MediaRequestBroker.attacker);

      // SECURE: authorization bound to the stable reserved owner -> refused.
      final secure = MediaRequestBroker.seeded().createRequestSafe(
        MediaRequestBroker.attacker,
        MediaRequestBroker.contestedPath,
      );
      expect(secure.granted, isFalse);
      expect(secure.stolenFromOwner, isFalse);
      expect(secure.effectiveOwner, MediaRequestBroker.victim);
      expect(secure.denyReason, contains('bound to owner'));

      // SECURE: the rightful owner may still claim their own reserved path.
      final rightful = MediaRequestBroker.seeded().createRequestSafe(
        MediaRequestBroker.victim,
        MediaRequestBroker.contestedPath,
      );
      expect(rightful.granted, isTrue);
      expect(rightful.effectiveOwner, MediaRequestBroker.victim);
    });
  });

  group('assistant_locked_device_capability_abuse', () {
    test(
      'assistant runs sensitive intent while locked; safe path re-checks',
      () {
        const gateway = AssistantGateway.lockedSample; // deviceLocked == true

        // VULN: the assistant reads the balance aloud on a LOCKED device.
        final vuln = gateway.invoke(AssistantCapability.readBalance);
        expect(vuln.deviceLocked, isTrue);
        expect(vuln.performed, isTrue);
        expect(vuln.sensitiveExposedWhileLocked, isTrue);
        expect(vuln.output, contains('balance'));

        // SECURE: the assistant re-checks the keyguard -> refused while locked.
        final secure = gateway.invokeSafe(AssistantCapability.readBalance);
        expect(secure.performed, isFalse);
        expect(secure.sensitiveExposedWhileLocked, isFalse);
        expect(secure.output, isNot(contains('balance')));
        expect(secure.denyReason, contains('unlock'));

        // SECURE: a non-sensitive capability still works while locked.
        final weather = gateway.invokeSafe(AssistantCapability.readWeather);
        expect(weather.performed, isTrue);
        expect(weather.sensitiveExposedWhileLocked, isFalse);

        // SECURE: once UNLOCKED, the sensitive capability is permitted.
        const unlocked = AssistantGateway(deviceLocked: false);
        final afterUnlock = unlocked.invokeSafe(
          AssistantCapability.readBalance,
        );
        expect(afterUnlock.performed, isTrue);
        expect(afterUnlock.sensitiveExposedWhileLocked, isFalse);
      },
    );
  });

  group('protected_data_access_via_input_validation', () {
    test(
      'check-before-canonicalize leaks protected id; safe path canonicalizes',
      () {
        const input = ResourceAuthorizer.evasiveInput;

        // VULN: naive deny on raw input, lookup on canonical -> protected leak.
        final vuln = ResourceAuthorizer.seeded().authorize(input);
        expect(vuln.granted, isTrue);
        expect(vuln.protectedLeaked, isTrue);
        expect(vuln.canonical, ResourceAuthorizer.protectedId);
        expect(vuln.data, ResourceAuthorizer.protectedData);

        // SECURE: canonicalize first, then deny-check -> refused.
        final secure = ResourceAuthorizer.seeded().authorizeSafe(input);
        expect(secure.granted, isFalse);
        expect(secure.protectedLeaked, isFalse);
        expect(secure.data, isNull);
        expect(secure.denyReason, contains('protected resource'));

        // SECURE: a genuinely public id is still served.
        final ok = ResourceAuthorizer.seeded().authorizeSafe(
          ResourceAuthorizer.publicId,
        );
        expect(ok.granted, isTrue);
        expect(ok.protectedLeaked, isFalse);
        expect(ok.data, 'theme=dark');
      },
    );
  });

  group('provider_metadata_to_filesystem_traversal', () {
    test('provider name traverses out of cache; safe path confines', () async {
      // VULN: a malicious provider display name escapes the plugin cache and
      // clobbers the app secrets.
      final plugin = await FilePickerPlugin.seeded();
      final vuln = await plugin.pickAndCache(ContentProvider.malicious);
      expect(vuln.wrote, isTrue);
      expect(vuln.escapedCacheRoot, isTrue);
      expect(vuln.resolvedPath, FilePickerPlugin.secretsPath);
      expect(
        await plugin.fileAt(FilePickerPlugin.secretsPath),
        ContentProvider.malicious.bytes,
      );
      expect(
        await plugin.fileAt(FilePickerPlugin.secretsPath),
        isNot(FilePickerPlugin.originalSecrets),
      );

      // SECURE: traversal in the provider name -> refused; secrets intact.
      final safePlugin = await FilePickerPlugin.seeded(tag: 'secure');
      final secure = await safePlugin.pickAndCacheSafe(
        ContentProvider.malicious,
      );
      expect(secure.wrote, isFalse);
      expect(secure.blocked, isTrue);
      expect(secure.escapedCacheRoot, isFalse);
      expect(secure.reason, contains('traversal'));
      expect(
        await safePlugin.fileAt(FilePickerPlugin.secretsPath),
        FilePickerPlugin.originalSecrets,
      );

      // SECURE: a benign provider name caches under the plugin cache root.
      final okPlugin = await FilePickerPlugin.seeded(tag: 'ok');
      final ok = await okPlugin.pickAndCacheSafe(ContentProvider.benign);
      expect(ok.wrote, isTrue);
      expect(ok.escapedCacheRoot, isFalse);
      expect(ok.resolvedPath, startsWith('${FilePickerPlugin.cacheRoot}/'));
    });
  });
}
