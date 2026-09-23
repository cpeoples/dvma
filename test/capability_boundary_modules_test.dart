import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/platform/default_role_holder_confusion/role_resolver.dart';
import 'package:dvma/modules/platform/persistable_uri_grant_abuse/persistable_uri_vault.dart';
import 'package:dvma/modules/platform/clipdata_uri_grant_leakage/clipdata_forwarder.dart';
import 'package:dvma/modules/platform/file_descriptor_capability_leakage/fd_capability_broker.dart';
import 'package:dvma/modules/platform/ordered_broadcast_result_injection/ordered_broadcast_bus.dart';
import 'package:dvma/modules/platform/remoteviews_widget_action_injection/widget_remote_views.dart';
import 'package:dvma/modules/platform/notification_action_authorization_bypass/notification_action_router.dart';
import 'package:dvma/modules/platform/custom_signature_permission_squatting/custom_permission_guard.dart';
import 'package:dvma/modules/platform/handoff_useractivity_injection/handoff_activity_receiver.dart';
import 'package:dvma/modules/platform/universal_link_aasa_confusion/universal_link_router.dart';
import 'package:dvma/modules/platform/app_clip_invocation_injection/app_clip_invoker.dart';
import 'package:dvma/modules/auth/identity_credential_presentation_binding/mdl_presentation_verifier.dart';

/// Regression suite for the Android 17 / iOS 26 capability-boundary family:
/// role/default-app confusion, persistent + ClipData + FD capability leakage,
/// ordered-broadcast result injection, RemoteViews/notification action abuse,
/// permission squatting, Handoff/Universal-Link/App-Clip injection, and mDL
/// presentation binding. Each test asserts the INSECURE path lets the untrusted
/// caller/payload through AND that the secure contrast fails closed, so an
/// accidental "fix" of the lab breaks CI.
void main() {
  group('default_role_holder_confusion', () {
    test('secret delegated to whichever app wins resolveActivity()', () {
      final vuln = RoleResolver().delegateSecret(RoleResolver.role);
      expect(vuln.delivered, isTrue);
      expect(vuln.roleHolderVerified, isFalse);
      expect(vuln.recipientPackage, RoleResolver.attackerPackage);
    });

    test('safe path verifies the RoleManager holder + signature', () {
      final blocked = RoleResolver().delegateSecretSafe(RoleResolver.role);
      expect(blocked.delivered, isFalse);
      expect(blocked.denyReason, isNotNull);
    });
  });

  group('persistable_uri_grant_abuse', () {
    const attackerGrant = UriGrant(
      uri: PersistableUriVault.attackerUri,
      providerAuthority: PersistableUriVault.attackerAuthority,
      persistable: true,
    );

    test('persisted grant survives revocation and provider swaps data', () {
      final vault = PersistableUriVault();
      vault.receiveGrant(attackerGrant);
      vault.endIntentAndRevokeTransient();
      final later = vault.readLater(attackerGrant);
      expect(later.survivesRevocation, isTrue);
      expect(later.readSucceeded, isTrue);
      expect(later.dataSwapped, isTrue);
    });

    test('safe path refuses to persist an untrusted-provider grant', () {
      final vault = PersistableUriVault();
      final blocked = vault.receiveGrantSafe(attackerGrant);
      expect(blocked.persisted, isFalse);
      expect(blocked.denyReason, isNotNull);
    });
  });

  group('clipdata_uri_grant_leakage', () {
    const leakyIntent = ForwardedIntent(
      action: 'android.intent.action.VIEW',
      explicitPackage: null,
      dataUri: 'content://com.dvma.app.share/thumb/9',
      clipUris: [ClipDataForwarder.privateContentUri],
      grantRead: true,
    );

    test('private URI capability rides ClipData to an implicit resolver', () {
      final vuln = ClipDataForwarder().send(leakyIntent);
      expect(vuln.capabilityForwarded, isTrue);
      expect(vuln.recipientCanRead, isTrue);
      expect(vuln.recipientPackage, ClipDataForwarder.attackerResolverPackage);
    });

    test('safe path sends explicit + never grants private URIs onward', () {
      final blocked = ClipDataForwarder().sendSafe(leakyIntent);
      expect(blocked.capabilityForwarded, isFalse);
      expect(blocked.denyReason, isNotNull);
    });
  });

  group('file_descriptor_capability_leakage', () {
    test('attacker receives an rw FD to the sensitive DB', () {
      final vuln = FdCapabilityBroker().openForCaller(
        FdCapabilityBroker.attackerCallerPackage,
        FdCapabilityBroker.sensitiveDbPath,
      );
      expect(vuln.fdReturned, isTrue);
      expect(vuln.callerChecked, isFalse);
      expect(vuln.sensitiveAccessGranted, isTrue);
      expect(vuln.bytesRead, FdCapabilityBroker.sensitiveBytes);
    });

    test('safe path refuses the sensitive resource for untrusted callers', () {
      final blocked = FdCapabilityBroker().openForCallerSafe(
        FdCapabilityBroker.attackerCallerPackage,
        FdCapabilityBroker.sensitiveDbPath,
      );
      expect(blocked.fdReturned, isFalse);
      expect(blocked.denyReason, isNotNull);
    });
  });

  group('ordered_broadcast_result_injection', () {
    OrderedBroadcastBus seeded() => OrderedBroadcastBus()
      ..register(OrderedBroadcastBus.attackerReceiver())
      ..register(OrderedBroadcastBus.appReceiver());

    test('higher-priority attacker receiver intercepts the pipeline first', () {
      final vuln = seeded().sendOrdered(OrderedBroadcastBus.legitimateResult);
      expect(vuln.resultTrusted, isTrue);
      expect(vuln.firstReceiverPackage, OrderedBroadcastBus.attackerPackage);
    });

    test('safe path drops the unsigned attacker + distrusts the result', () {
      final blocked = seeded().sendOrderedSafe(
        OrderedBroadcastBus.legitimateResult,
      );
      expect(blocked.resultTrusted, isFalse);
      expect(
        blocked.firstReceiverPackage,
        isNot(OrderedBroadcastBus.attackerPackage),
      );
      expect(blocked.denyReason, isNotNull);
    });
  });

  group('remoteviews_widget_action_injection', () {
    final attackerExtras = <String, Object?>{
      'action': WidgetRemoteViews.transferAction,
      'amount': WidgetRemoteViews.attackerAmount,
      'toAccount': WidgetRemoteViews.attackerAccount,
    };

    test('widget-config extras drive an unauthenticated transfer', () {
      final rv = WidgetRemoteViews()..configure(attackerExtras);
      final vuln = rv.tap();
      expect(vuln.actionPerformed, isTrue);
      expect(vuln.reauthenticated, isFalse);
      expect(vuln.amount, WidgetRemoteViews.attackerAmount);
    });

    test('safe path neutralizes attacker extras (no attacker transfer)', () {
      final rv = WidgetRemoteViews()..configureSafe(attackerExtras);
      final safe = rv.tapSafe();
      expect(safe.action, isNot(WidgetRemoteViews.transferAction));
      expect(safe.amount, isNot(WidgetRemoteViews.attackerAmount));
      expect(safe.toAccount, isNot(WidgetRemoteViews.attackerAccount));
    });
  });

  group('notification_action_authorization_bypass', () {
    test('sensitive action runs via trampoline with no fresh auth', () {
      final vuln = NotificationActionRouter().invokeAction(
        NotificationActionRouter.sensitiveAction,
      );
      expect(vuln.performed, isTrue);
      expect(vuln.freshAuthRequired, isTrue);
      expect(vuln.freshAuthPresented, isFalse);
    });

    test('safe path blocks until fresh auth is presented', () {
      final blocked = NotificationActionRouter().invokeActionSafe(
        NotificationActionRouter.sensitiveAction,
      );
      expect(blocked.performed, isFalse);
      expect(blocked.denyReason, isNotNull);
    });
  });

  group('custom_signature_permission_squatting', () {
    test('normal-level guard is trivially held by the attacker app', () {
      final vuln = CustomPermissionGuard().call(
        CustomPermissionGuard.attackerApp(),
      );
      expect(vuln.callAllowed, isTrue);
      expect(vuln.guardEffective, isFalse);
      expect(vuln.attackerHeldPermission, isTrue);
    });

    test('signature guard + identity check refuses the squatter', () {
      final blocked = CustomPermissionGuard().callSafe(
        CustomPermissionGuard.attackerApp(),
      );
      expect(blocked.callAllowed, isFalse);
      expect(blocked.denyReason, isNotNull);
    });
  });

  group('handoff_useractivity_injection', () {
    final crafted = HandoffUserActivity(
      activityType: HandoffActivityReceiver.expectedActivityType,
      userInfo: const {
        'accountId': HandoffActivityReceiver.attackerTargetAccount,
        'action': 'open_resource',
      },
      webpageURL: null,
      sourceDeviceTrusted: false,
      boundAccountId: HandoffActivityReceiver.attackerTargetAccount,
    );

    test('crafted continuation drives the app to a foreign account', () {
      final vuln = HandoffActivityReceiver().continueActivity(crafted);
      expect(vuln.stateApplied, isTrue);
      expect(vuln.accountBound, isFalse);
      expect(vuln.targetAccount, HandoffActivityReceiver.attackerTargetAccount);
    });

    test('safe path requires account binding + validated source', () {
      final blocked = HandoffActivityReceiver().continueActivitySafe(crafted);
      expect(blocked.stateApplied, isFalse);
      expect(blocked.denyReason, isNotNull);
    });
  });

  group('universal_link_aasa_confusion', () {
    test('crafted wildcard/redirect link reaches a sensitive handler', () {
      final router = UniversalLinkRouter();
      final vuln = router.openUniversalLink(
        UniversalLinkRouter.craftedWildcardLink,
      );
      expect(vuln.routed, isTrue);
      expect(vuln.reachedSensitiveHandler, isTrue);
      expect(vuln.pathMatchTooBroad, isTrue);
    });

    test('tight matching rejects crafted, allows the genuine link', () {
      final router = UniversalLinkRouter();
      final blocked = router.openUniversalLinkSafe(
        UniversalLinkRouter.craftedWildcardLink,
      );
      expect(blocked.routed, isFalse);
      expect(blocked.denyReason, isNotNull);

      final ok = router.openUniversalLinkSafe(UniversalLinkRouter.genuineLink);
      expect(ok.routed, isTrue);
    });
  });

  group('app_clip_invocation_injection', () {
    test('crafted invocation performs a privileged action, no re-auth', () {
      final vuln = AppClipInvoker().invoke(AppClipInvoker.craftedInvocation);
      expect(vuln.actionPerformed, isTrue);
      expect(vuln.invocationValidated, isFalse);
      expect(vuln.reauthenticated, isFalse);
    });

    test('safe path validates the invocation + re-authenticates', () {
      final blocked = AppClipInvoker().invokeSafe(
        AppClipInvoker.craftedInvocation,
      );
      expect(blocked.actionPerformed, isFalse);
      expect(blocked.denyReason, isNotNull);
    });
  });

  group('identity_credential_presentation_binding', () {
    const replayed = MdlPresentation(
      issuerSignatureValid: true,
      deviceSignedOverSessionTranscript:
          MdlPresentationVerifier.foreignSessionTranscript,
      userPresent: false,
      holderClaims: MdlPresentationVerifier.holderClaims,
    );
    const inSession = MdlPresentation(
      issuerSignatureValid: true,
      deviceSignedOverSessionTranscript:
          MdlPresentationVerifier.currentSessionTranscript,
      userPresent: true,
      holderClaims: MdlPresentationVerifier.holderClaims,
    );

    test('replayed presentation from another session is accepted', () {
      final vuln = MdlPresentationVerifier().verify(replayed);
      expect(vuln.accepted, isTrue);
      expect(vuln.boundToSession, isFalse);
      expect(vuln.replayAccepted, isTrue);
    });

    test('safe path binds to session transcript + user presence', () {
      final verifier = MdlPresentationVerifier();
      final blocked = verifier.verifySafe(replayed);
      expect(blocked.accepted, isFalse);
      expect(blocked.denyReason, isNotNull);

      final ok = verifier.verifySafe(inSession);
      expect(ok.accepted, isTrue);
      expect(ok.boundToSession, isTrue);
    });
  });
}
