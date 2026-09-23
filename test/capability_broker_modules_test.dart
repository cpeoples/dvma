import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/system_provider/privileged_input_provider_injection/ime_event_injector.dart';
import 'package:dvma/modules/system_provider/companion_device_pairing_confusion/companion_device_manager.dart';
import 'package:dvma/modules/system_provider/device_policy_mdm_capability_abuse/device_policy_controller.dart';
import 'package:dvma/modules/system_provider/vpn_provider_trust_anchor_abuse/vpn_tunnel.dart';
import 'package:dvma/modules/system_provider/notification_intelligence_ai_processing/notification_ai_pipeline.dart';
import 'package:dvma/modules/system_provider/assist_screen_context_ai_exposure/assist_context_provider.dart';
import 'package:dvma/modules/system_provider/app_group_shared_container_amplification/app_group_container.dart';
import 'package:dvma/modules/system_provider/extension_activation_input_confusion/share_extension_handler.dart';
import 'package:dvma/modules/system_provider/lockscreen_control_action_authorization/control_widget_intent.dart'
    as lockscreen;
import 'package:dvma/modules/platform/cross_profile_data_capability_leakage/cross_profile_router.dart';

/// Regression suite for the Mobile Capability Broker Abuse modules: an app that
/// becomes a privileged system actor/provider is a broker between an untrusted
/// actor and a privileged capability. Each test asserts the INSECURE path
/// injects / over-grants / mis-applies / MITMs / prompt-injects / leaks /
/// crosses a tenant boundary AND that the secure contrast blocks it, so an
/// accidental "fix" of the lab fails CI.
void main() {
  group('privileged_input_provider_injection', () {
    test('untrusted caller injects events; safe path checks permission', () {
      final ime = ImeEventInjector();
      final vuln = ime.inject(
        ImeEventInjector.attackerPackage,
        ImeEventInjector.attackerBatch,
      );
      expect(vuln.performed, isTrue);
      expect(vuln.callerAuthorized, isFalse);
      expect(vuln.sensitiveActionConfirmed, isTrue);

      final safe = ImeEventInjector().injectSafe(
        ImeEventInjector.attackerPackage,
        ImeEventInjector.attackerBatch,
      );
      expect(safe.performed, isFalse);
      expect(safe.denyReason, isNotNull);

      // System caller with the permission is still allowed on the safe path.
      final system = ImeEventInjector().injectSafe(
        ImeEventInjector.systemPackage,
        ImeEventInjector.attackerBatch,
      );
      expect(system.performed, isTrue);
    });
  });

  group('companion_device_pairing_confusion', () {
    test(
      'paired != authorized for every capability; safe path binds trust',
      () {
        final mgr = CompanionDeviceManager();
        final vuln = mgr.requestCapability(
          CompanionDeviceManager.spoofedWatch,
          CompanionCapability.unlockDoor,
        );
        expect(vuln.granted, isTrue);
        expect(vuln.overPrivileged, isTrue);

        final safe = CompanionDeviceManager().requestCapabilitySafe(
          CompanionDeviceManager.spoofedWatch,
          CompanionCapability.unlockDoor,
        );
        expect(safe.granted, isFalse);
        expect(safe.denyReason, isNotNull);

        // A verified device may still use a capability matching its trust.
        final ok = CompanionDeviceManager().requestCapabilitySafe(
          CompanionDeviceManager.verifiedWatch,
          CompanionCapability.readNotifications,
        );
        expect(ok.granted, isTrue);
      },
    );
  });

  group('device_policy_mdm_capability_abuse', () {
    test(
      'untrusted caller applies device-wide policy; safe path verifies admin',
      () {
        final vuln = DevicePolicyController().applyPolicy(
          DevicePolicyController.attackerPackage,
          DevicePolicy.wipeData,
          null,
        );
        expect(vuln.applied, isTrue);
        expect(vuln.callerIsActiveAdmin, isFalse);

        final safe = DevicePolicyController().applyPolicySafe(
          DevicePolicyController.attackerPackage,
          DevicePolicy.wipeData,
          null,
        );
        expect(safe.applied, isFalse);
        expect(safe.denyReason, isNotNull);

        // Registered admin applying a VALID parameter is allowed.
        final ok = DevicePolicyController().applyPolicySafe(
          DevicePolicyController.registeredAdmin,
          DevicePolicy.setPasswordQuality,
          DevicePolicyController.passwordQualityAlphanumeric,
        );
        expect(ok.applied, isTrue);

        // Registered admin applying an INVALID (weak) parameter is rejected.
        final weak = DevicePolicyController().applyPolicySafe(
          DevicePolicyController.registeredAdmin,
          DevicePolicy.setPasswordQuality,
          DevicePolicyController.passwordQualityWeak,
        );
        expect(weak.applied, isFalse);
      },
    );
  });

  group('vpn_provider_trust_anchor_abuse', () {
    test(
      'rogue endpoint accepted (MITM); safe path validates the trust anchor',
      () {
        final vuln = VpnTunnel().connect(VpnTunnel.rogueEndpoint);
        expect(vuln.established, isTrue);
        expect(vuln.mitmPossible, isTrue);

        final safe = VpnTunnel().connectSafe(VpnTunnel.rogueEndpoint);
        expect(safe.established, isFalse);
        expect(safe.denyReason, isNotNull);

        // A genuine endpoint with a trusted chain + matching hostname connects.
        final ok = VpnTunnel().connectSafe(VpnTunnel.genuineEndpoint);
        expect(ok.established, isTrue);
        expect(ok.mitmPossible, isFalse);
      },
    );
  });

  group('notification_intelligence_ai_processing', () {
    test(
      'malicious notification injects the AI; safe path redacts + isolates',
      () {
        final vuln = NotificationAiPipeline().process(
          NotificationAiPipeline.maliciousNotification,
        );
        expect(vuln.promptInjected, isTrue);
        expect(vuln.actionTriggered, isTrue);
        expect(vuln.leaked, contains(NotificationAiPipeline.userOtp));

        final safe = NotificationAiPipeline().processSafe(
          NotificationAiPipeline.maliciousNotification,
        );
        expect(safe.promptInjected, isFalse);
        expect(safe.actionTriggered, isFalse);
        expect(safe.leaked, isNot(contains(NotificationAiPipeline.userOtp)));
      },
    );
  });

  group('assist_screen_context_ai_exposure', () {
    test('sensitive screen context shared + acted on; safe path opts out', () {
      final vuln = AssistContextProvider().shareContext(
        AssistContextProvider.bankingScreen(),
      );
      expect(vuln.sensitiveShared, isTrue);
      expect(vuln.actionTriggered, isTrue);
      expect(vuln.leaked, contains(AssistContextProvider.onScreenSecret));

      final safe = AssistContextProvider().shareContextSafe(
        AssistContextProvider.bankingScreen(),
      );
      expect(safe.sensitiveShared, isFalse);
      expect(safe.actionTriggered, isFalse);
      expect(
        safe.leaked,
        isNot(contains(AssistContextProvider.onScreenSecret)),
      );
    });
  });

  group('app_group_shared_container_amplification', () {
    test(
      'low-trust extension reads shared secret; safe path scopes per-item',
      () {
        final vuln = AppGroupContainer()..seedAsMainApp();
        final read = vuln.read(
          AppGroupContainer.keyboardExtension,
          AppGroupContainer.authTokenKey,
        );
        expect(read.read, isTrue);
        expect(read.sensitiveExposed, isTrue);
        expect(read.value, AppGroupContainer.authTokenValue);

        final safe = AppGroupContainer()..seedAsMainApp();
        final denied = safe.readSafe(
          AppGroupContainer.keyboardExtension,
          AppGroupContainer.authTokenKey,
        );
        expect(denied.read, isFalse);
        expect(denied.sensitiveExposed, isFalse);
        expect(denied.denyReason, isNotNull);

        // The main app itself may still read its own sensitive item.
        final ok = (AppGroupContainer()..seedAsMainApp()).readSafe(
          AppGroupContainer.mainApp,
          AppGroupContainer.authTokenKey,
        );
        expect(ok.read, isTrue);
      },
    );
  });

  group('extension_activation_input_confusion', () {
    test(
      'activation != authorization: crafted payload acted on; safe validates',
      () async {
        final vuln = await ShareExtensionHandler().handle(
          ShareExtensionHandler.maliciousFilePayload,
        );
        expect(vuln.performed, isTrue);
        expect(vuln.inputValidated, isFalse);
        expect(vuln.unsafe, isTrue);

        final safe = await ShareExtensionHandler().handleSafe(
          ShareExtensionHandler.maliciousFilePayload,
        );
        expect(safe.performed, isFalse);
        expect(safe.denyReason, isNotNull);

        // A benign, validatable payload is accepted on the safe path.
        final ok = await ShareExtensionHandler().handleSafe(
          ShareExtensionHandler.benignFilePayload,
        );
        expect(ok.performed, isTrue);
      },
    );
  });

  group('lockscreen_control_action_authorization', () {
    test(
      'sensitive intent runs from locked screen; safe path requires auth',
      () {
        final vuln = lockscreen.ControlWidgetIntentRunner().invoke(
          lockscreen.ControlWidgetIntentRunner.unlockFrontDoor,
          lockscreen.Surface.lockScreen,
          deviceLocked: true,
        );
        expect(vuln.performed, isTrue);
        expect(vuln.authRequired, isFalse);
        expect(vuln.unsafe, isTrue);

        final safe = lockscreen.ControlWidgetIntentRunner().invokeSafe(
          lockscreen.ControlWidgetIntentRunner.unlockFrontDoor,
          lockscreen.Surface.lockScreen,
          deviceLocked: true,
        );
        expect(safe.performed, isFalse);
        expect(safe.authRequired, isTrue);
        expect(safe.denyReason, isNotNull);

        // A non-sensitive intent runs from the lock screen on the safe path.
        final ok = lockscreen.ControlWidgetIntentRunner().invokeSafe(
          lockscreen.ControlWidgetIntentRunner.togglePublicFlashlight,
          lockscreen.Surface.lockScreen,
          deviceLocked: true,
        );
        expect(ok.performed, isTrue);
      },
    );
  });

  group('cross_profile_data_capability_leakage', () {
    test(
      'work secret crosses to personal surface; safe path enforces policy',
      () {
        final vuln = CrossProfileRouter().forward(
          CrossProfileRouter.workCredential,
          Profile.work,
          Profile.personal,
          CrossProfileRouter.personalShareSheet,
        );
        expect(vuln.crossed, isTrue);
        expect(vuln.boundaryViolated, isTrue);

        final safe = CrossProfileRouter().forwardSafe(
          CrossProfileRouter.workCredential,
          Profile.work,
          Profile.personal,
          CrossProfileRouter.personalShareSheet,
        );
        expect(safe.crossed, isFalse);
        expect(safe.denyReason, isNotNull);

        // A non-sensitive, allowlisted item may cross with the affordance.
        final ok = CrossProfileRouter().forwardSafe(
          CrossProfileRouter.publicLink,
          Profile.work,
          Profile.personal,
          CrossProfileRouter.personalShareSheet,
          userAffordanceGranted: true,
        );
        expect(ok.crossed, isTrue);
      },
    );
  });
}
