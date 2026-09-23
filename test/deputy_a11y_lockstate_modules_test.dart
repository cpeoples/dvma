import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/platform/content_uri_resolver_confused_deputy/content_resolver_proxy.dart';
import 'package:dvma/modules/platform/accessibility_service_privilege_abuse/a11y_service.dart';
import 'package:dvma/modules/platform/notification_listener_authorization_bypass/notification_access_manager.dart';
import 'package:dvma/modules/platform/background_activity_launch_abuse/activity_launcher.dart';
import 'package:dvma/modules/privacy/lock_state_confusion_data_exposure/lock_screen_reader.dart';
import 'package:dvma/modules/privacy/privacy_control_alternate_path_bypass/privacy_gated_resource.dart';

/// Regression suite for the confused-deputy / a11y-abuse / listener-bypass /
/// background-launch / lock-state / privacy-alternate-path training modules.
/// Each test asserts the INSECURE path proxies / escalates / reads / launches /
/// leaks AND that the secure contrast blocks it, so an accidental "fix" of the
/// lab fails CI.
void main() {
  group('content_uri_resolver_confused_deputy', () {
    test(
      'resolver proxies privileged authority; safe path validates caller',
      () {
        const uri = ContentResolverProxy.privilegedUri;

        // VULN: the app proxies the attacker-supplied URI with its OWN
        // privileges, reading a provider the caller could never reach.
        final vuln = ContentResolverProxy.seeded().openUri(
          ContentResolverProxy.attackerUid,
          uri,
        );
        expect(vuln.opened, isTrue);
        expect(vuln.blocked, isFalse);
        expect(vuln.privileged, isTrue);
        expect(vuln.confusedDeputy, isTrue);
        expect(vuln.authority, ContentResolverProxy.privateAuthority);
        expect(vuln.data, ContentResolverProxy.privateData);
        expect(vuln.data, contains('oauth_refresh_token'));

        // SECURE: untrusted caller lacks the permission -> refused.
        final secure = ContentResolverProxy.seeded().openUriSafe(
          ContentResolverProxy.attackerUid,
          uri,
        );
        expect(secure.opened, isFalse);
        expect(secure.blocked, isTrue);
        expect(secure.confusedDeputy, isFalse);
        expect(secure.data, isNull);
        expect(secure.denyReason, isNotNull);

        // SECURE: a caller GRANTED the required permission may read it.
        final granted = ContentResolverProxy.seeded().openUriSafe(
          ContentResolverProxy.appUid,
          uri,
          grantedPermissions: const {ContentResolverProxy.privatePermission},
        );
        expect(granted.opened, isTrue);
        expect(granted.data, ContentResolverProxy.privateData);

        // SECURE: a benign public authority is still served to anyone.
        final benign = ContentResolverProxy.seeded().openUriSafe(
          ContentResolverProxy.attackerUid,
          ContentResolverProxy.benignUri,
        );
        expect(benign.opened, isTrue);
        expect(benign.privileged, isFalse);
        expect(benign.confusedDeputy, isFalse);
      },
    );
  });

  group('accessibility_service_privilege_abuse', () {
    test(
      'background launch runs unchecked; safe path requires event+allowlist',
      () {
        const action = A11yService.maliciousLaunch;

        // VULN: the service launches a background activity with no state/event
        // check.
        final vuln = A11yService(userEnabled: true).perform(action);
        expect(vuln.performed, isTrue);
        expect(vuln.blocked, isFalse);
        expect(vuln.privilegeAbused, isTrue);
        expect(vuln.kind, A11yActionKind.launchActivityFromBackground);
        expect(vuln.effect, contains('background'));

        // SECURE: not on the self-initiable allowlist + no foreground event ->
        // refused.
        final secure = A11yService(userEnabled: true).performSafe(action);
        expect(secure.performed, isFalse);
        expect(secure.blocked, isTrue);
        expect(secure.privilegeAbused, isFalse);
        expect(secure.denyReason, contains('foreground'));

        // SECURE: a disabled service refuses even an allowlisted action.
        final disabled = A11yService(userEnabled: false)
            .performSafe(A11yService.benignRead);
        expect(disabled.performed, isFalse);
        expect(disabled.blocked, isTrue);
        expect(disabled.denyReason, contains('not user-enabled'));

        // SECURE: a benign assistive read tied to a foreground event succeeds.
        final ok = A11yService(userEnabled: true)
            .performSafe(A11yService.benignRead);
        expect(ok.performed, isTrue);
        expect(ok.blocked, isFalse);
        expect(ok.privilegeAbused, isFalse);
      },
    );
  });

  group('notification_listener_authorization_bypass', () {
    test('unverified listener reads all; safe path requires unlocked grant', () {
      const attacker = NotificationAccessManager.attackerListener;

      // VULN: access granted with no consent record; listener reads all
      // notifications even though the device is locked.
      final vuln = NotificationAccessManager.seeded(deviceUnlocked: false)
          .bindListener(attacker);
      expect(vuln.granted, isTrue);
      expect(vuln.blocked, isFalse);
      expect(vuln.contentsLeaked, isTrue);
      expect(vuln.read, isNotEmpty);
      expect(vuln.read.map((n) => n.text).join(), contains('OTP 4471'));

      // SECURE: unverified component -> refused.
      final unverified = NotificationAccessManager.seeded(deviceUnlocked: true)
          .bindListenerSafe(attacker);
      expect(unverified.granted, isFalse);
      expect(unverified.blocked, isTrue);
      expect(unverified.contentsLeaked, isFalse);
      expect(unverified.read, isEmpty);
      expect(unverified.denyReason, contains('not verified'));

      // SECURE: verified component but grant recorded while LOCKED -> refused.
      final lockedGrant = NotificationAccessManager.seeded(
        deviceUnlocked: true,
        grants: const [
          ListenerGrant(
            component: NotificationAccessManager.trustedListener,
            recordedWhileUnlocked: false,
            userConfirmed: true,
          ),
        ],
      ).bindListenerSafe(NotificationAccessManager.trustedListener);
      expect(lockedGrant.blocked, isTrue);
      expect(lockedGrant.denyReason, contains('lock screen'));

      // SECURE: verified component + user-confirmed grant recorded while
      // UNLOCKED -> allowed.
      final ok = NotificationAccessManager.seeded(
        deviceUnlocked: true,
        grants: const [
          ListenerGrant(
            component: NotificationAccessManager.trustedListener,
            recordedWhileUnlocked: true,
            userConfirmed: true,
          ),
        ],
      ).bindListenerSafe(NotificationAccessManager.trustedListener);
      expect(ok.granted, isTrue);
      expect(ok.blocked, isFalse);
      expect(ok.read, isNotEmpty);
    });
  });

  group('background_activity_launch_abuse', () {
    test('background caller reaches sensitive UI; safe path enforces BAL', () {
      const caller = ActivityLauncher.backgroundAttacker;
      const activity = ActivityLauncher.fakeConsentDialog;

      // VULN: a background caller reaches the security-sensitive activity.
      final vuln = ActivityLauncher().launch(caller, activity);
      expect(vuln.launched, isTrue);
      expect(vuln.blocked, isFalse);
      expect(vuln.backgroundLaunchAbuse, isTrue);
      expect(vuln.callerForeground, isFalse);
      expect(vuln.sensitive, isTrue);

      // SECURE: background + no token -> refused.
      final secure = ActivityLauncher().launchSafe(caller, activity);
      expect(secure.launched, isFalse);
      expect(secure.blocked, isTrue);
      expect(secure.backgroundLaunchAbuse, isFalse);
      expect(secure.denyReason, contains('background-activity-launch'));

      // SECURE: a background caller WITH a valid launch token is allowed.
      final tokened = ActivityLauncher().launchSafe(
        const LaunchCaller(
          package: ActivityLauncher.attackerPackage,
          inForeground: false,
          launchToken: ActivityLauncher.validLaunchToken,
        ),
        activity,
      );
      expect(tokened.launched, isTrue);
      expect(tokened.blocked, isFalse);

      // SECURE: a foreground caller is allowed.
      final foreground = ActivityLauncher().launchSafe(
        const LaunchCaller(package: 'com.dvma.app', inForeground: true),
        activity,
      );
      expect(foreground.launched, isTrue);
      expect(foreground.backgroundLaunchAbuse, isFalse);
    });
  });

  group('lock_state_confusion_data_exposure', () {
    test('alternate path leaks while locked; safe path re-checks keyguard', () {
      const surface = LockScreenSurface.sample; // locked == true
      const reader = LockScreenReader();

      // VULN: the VoiceOver path returns full protected content while locked.
      final vuln = reader.read(surface, path: AccessPath.voiceOver);
      expect(vuln.locked, isTrue);
      expect(vuln.leakedWhileLocked, isTrue);
      expect(vuln.displayed, surface.protectedContent);
      expect(vuln.displayed, contains('balance'));

      // SECURE: the keyguard is re-checked -> only redacted content.
      final secure = reader.readSafe(surface, path: AccessPath.voiceOver);
      expect(secure.leakedWhileLocked, isFalse);
      expect(secure.displayed, surface.redactedContent);
      expect(secure.displayed, isNot(contains('balance')));

      // SECURE: once UNLOCKED, the full content is permitted.
      final unlocked = LockScreenSurface(
        locked: false,
        protectedContent: surface.protectedContent,
        redactedContent: surface.redactedContent,
      );
      final afterUnlock = reader.readSafe(unlocked, path: AccessPath.voiceOver);
      expect(afterUnlock.leakedWhileLocked, isFalse);
      expect(afterUnlock.displayed, unlocked.protectedContent);
    });
  });

  group('privacy_control_alternate_path_bypass', () {
    test(
      'alternate cache bypasses consent; safe path funnels through gate',
      () {
        // VULN: read from the app-group cache with consent NOT granted.
        final vuln = PrivacyGatedResource(consentGranted: false)
            .readViaAlternatePath();
        expect(vuln.granted, isTrue);
        expect(vuln.blocked, isFalse);
        expect(vuln.consentChecked, isFalse);
        expect(vuln.bypassedConsent, isTrue);
        expect(vuln.records, isNotEmpty);
        expect(vuln.records.map((c) => c.name).join(), contains('Oncology'));

        // SECURE: the single gated accessor refuses without consent.
        final denied = PrivacyGatedResource(consentGranted: false).readGated();
        expect(denied.granted, isFalse);
        expect(denied.blocked, isTrue);
        expect(denied.consentChecked, isTrue);
        expect(denied.bypassedConsent, isFalse);
        expect(denied.records, isEmpty);

        // SECURE: with consent granted, the gated accessor serves the data and
        // the consent gate was consulted.
        final consented = PrivacyGatedResource(consentGranted: true)
            .readGated();
        expect(consented.granted, isTrue);
        expect(consented.consentChecked, isTrue);
        expect(consented.bypassedConsent, isFalse);
        expect(consented.records, isNotEmpty);
      },
    );
  });
}
