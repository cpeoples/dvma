import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/modules/platform/dynamic_broadcast_receiver_exposure/dynamic_receiver_registry.dart';
import 'package:dvma/modules/platform/privileged_service_binding_exposure/service_binder_host.dart';
import 'package:dvma/modules/platform/activity_task_stack_hijacking/task_stack_manager.dart';
import 'package:dvma/modules/platform/activity_alias_exposure/activity_alias_router.dart';
import 'package:dvma/modules/native_bridge/webview_safe_browsing_disabled/safe_browsing_webview.dart';
import 'package:dvma/modules/native_bridge/webview_remote_debugging_enabled/debuggable_webview.dart';
import 'package:dvma/modules/native_bridge/webview_url_loading_policy_confusion/url_loading_policy.dart';
import 'package:dvma/modules/platform/platform_version_security_fallback/platform_version_gate.dart';
import 'package:dvma/modules/platform/intent_redirection/intent_model.dart';

/// Regression suite for the MASTG-aligned IPC / WebView-config / version-gate
/// family. These labs cover boundaries that live in the manifest, the binding
/// model, or the WebView configuration rather than in a single Intent payload.
/// Each test asserts the INSECURE path lets the untrusted caller / crafted URL
/// / old-OS device through AND that the secure contrast fails closed, so an
/// accidental "fix" of the lab breaks CI.
void main() {
  group('dynamic_broadcast_receiver_exposure', () {
    test('exported runtime receiver runs sensitive action for attacker', () {
      final reg = DynamicReceiverRegistry();
      reg.register(DynamicReceiverRegistry.promoAction);
      final vuln = reg.deliver(
        DynamicReceiverRegistry.promoAction,
        DynamicReceiverRegistry.attackerPackage,
      );
      expect(vuln.delivered, isTrue);
      expect(vuln.senderAuthorized, isFalse);
    });

    test('RECEIVER_NOT_EXPORTED + signature permission drops attacker', () {
      final reg = DynamicReceiverRegistry();
      reg.registerSafe(DynamicReceiverRegistry.promoAction);
      final blocked = reg.deliver(
        DynamicReceiverRegistry.promoAction,
        DynamicReceiverRegistry.attackerPackage,
      );
      expect(blocked.delivered, isFalse);
      expect(blocked.denyReason, isNotNull);
    });
  });

  group('privileged_service_binding_exposure', () {
    test('any caller binds and reads the secret over the binder', () {
      final host = ServiceBinderHost();
      final bind = host.bind(ServiceBinderHost.attackerPackage);
      expect(bind.bound, isTrue);
      expect(bind.callerChecked, isFalse);
      final call = bind.binder!.readSecret();
      expect(call.privilegedCallSucceeded, isTrue);
      expect(call.value, ServiceBinderHost.secret);
    });

    test('safe bind enforces caller identity before returning a binder', () {
      final host = ServiceBinderHost();
      final blocked = host.bindSafe(ServiceBinderHost.attackerPackage);
      expect(blocked.bound, isFalse);
      expect(blocked.denyReason, isNotNull);

      final ok = host.bindSafe(ServiceBinderHost.trustedPackage);
      expect(ok.bound, isTrue);
      expect(ok.binder!.readSecret().privilegedCallSucceeded, isTrue);
    });
  });

  group('activity_task_stack_hijacking', () {
    test('malicious activity lands atop the victim task via affinity', () {
      final mgr = TaskStackManager()..seedVictimTask();
      final vuln = mgr.launch(TaskStackManager.maliciousActivity);
      expect(vuln.hijacked, isTrue);
      expect(vuln.appearsInVictimTask, isTrue);
    });

    test('safe launch isolates the malicious activity in its own task', () {
      final mgr = TaskStackManager()..seedVictimTask();
      final blocked = mgr.launchSafe(TaskStackManager.maliciousActivity);
      expect(blocked.hijacked, isFalse);
      expect(blocked.appearsInVictimTask, isFalse);
    });
  });

  group('activity_alias_exposure', () {
    test('exported alias reaches the protected target activity', () {
      final router = ActivityAliasRouter();
      final vuln = router.launchViaAlias(ActivityAliasRouter.attackerPackage);
      expect(vuln.launched, isTrue);
      expect(vuln.targetProtected, isTrue);
      expect(vuln.aliasBypassedProtection, isTrue);
    });

    test('safe alias echoes the target protection and refuses attacker', () {
      final router = ActivityAliasRouter();
      final blocked = router.launchViaAliasSafe(
        ActivityAliasRouter.attackerPackage,
      );
      expect(blocked.launched, isFalse);
      expect(blocked.denyReason, isNotNull);
    });
  });

  group('webview_safe_browsing_disabled', () {
    test('disabled Safe Browsing loads a known-bad URL unwarned', () {
      final vuln = SafeBrowsingWebView.insecure.navigate(
        SafeBrowsingWebView.knownBadUrl,
      );
      expect(vuln.loaded, isTrue);
      expect(vuln.safeBrowsingEnabled, isFalse);
      expect(vuln.threatBlocked, isFalse);
    });

    test('Safe Browsing on blocks the threat but allows benign URLs', () {
      final blocked = SafeBrowsingWebView.secure.navigateSafe(
        SafeBrowsingWebView.knownBadUrl,
      );
      expect(blocked.loaded, isFalse);
      expect(blocked.threatBlocked, isTrue);

      final ok = SafeBrowsingWebView.secure.navigateSafe(
        SafeBrowsingWebView.benignUrl,
      );
      expect(ok.loaded, isTrue);
    });
  });

  group('webview_remote_debugging_enabled', () {
    test('debugging left on in release exposes web-context secrets', () {
      final vuln = DebuggableWebView(
        debuggingEnabled: true,
        isReleaseBuild: true,
      ).attachInspector();
      expect(vuln.inspectorAttached, isTrue);
      expect(vuln.debuggingEnabled, isTrue);
      expect(vuln.secretsExposed, isTrue);
      expect(vuln.exposedToken, DebuggableWebView.sessionToken);
    });

    test('safe config disables debugging in release builds', () {
      final blocked = DebuggableWebView(
        debuggingEnabled: true,
        isReleaseBuild: true,
      ).configureSafe(isReleaseBuild: true);
      expect(blocked.inspectorAttached, isFalse);
      expect(blocked.denyReason, isNotNull);
    });
  });

  group('webview_url_loading_policy_confusion', () {
    test('naive contains() check lets crafted URLs bypass the policy', () {
      final policy = UrlLoadingPolicy();
      for (final url in UrlLoadingPolicy.craftedBypassUrls) {
        final vuln = policy.shouldOverride(url);
        expect(vuln.loaded, isTrue, reason: 'expected bypass for $url');
        expect(vuln.policyBypassed, isTrue, reason: url);
      }
    });

    test(
      'canonicalizing policy rejects crafted URLs, allows the genuine one',
      () {
        final policy = UrlLoadingPolicy();
        for (final url in UrlLoadingPolicy.craftedBypassUrls) {
          final blocked = policy.shouldOverrideSafe(url);
          expect(blocked.loaded, isFalse, reason: 'should reject $url');
          expect(blocked.denyReason, isNotNull, reason: url);
        }
        final ok = policy.shouldOverrideSafe(UrlLoadingPolicy.genuineUrl);
        expect(ok.loaded, isTrue);
      },
    );
  });

  group('platform_version_security_fallback', () {
    test('old OS silently falls back to an insecure key store', () {
      final vuln = PlatformVersionGate().storeKey(
        PlatformVersionGate.oldOsVersion,
      );
      expect(vuln.stored, isTrue);
      expect(vuln.hardwareBacked, isFalse);
      expect(vuln.proceededInsecurely, isTrue);
    });

    test(
      'safe gate fails closed on old OS, hardware-backs on supported OS',
      () {
        final blocked = PlatformVersionGate().storeKeySafe(
          PlatformVersionGate.oldOsVersion,
        );
        expect(blocked.stored, isFalse);
        expect(blocked.denyReason, isNotNull);

        final ok = PlatformVersionGate().storeKeySafe(
          PlatformVersionGate.newOsVersion,
        );
        expect(ok.stored, isTrue);
        expect(ok.hardwareBacked, isTrue);
      },
    );
  });

  group('intent_redirection', () {
    test(
      'exported handler forwards a nested intent to an internal component',
      () {
        final attacker = AppIntent(
          action: 'VIEW',
          target: 'ExportedProxyActivity',
          extras: {
            'forward_intent': AppIntent(
              action: 'ADMIN',
              target: 'InternalAdminActivity',
            ),
          },
        );
        final result = IntentRouter.handleExported(attacker);
        expect(result.redirected, isTrue);
        expect(result.dispatchedTo, 'InternalAdminActivity');

        // A validating handler rejects redirection to internal components.
        final secure = IntentRouter.secureHandleExported(attacker);
        expect(secure.dispatchedTo, 'REJECTED');
      },
    );
  });
}
