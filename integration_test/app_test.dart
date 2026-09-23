// Master DVMA integration test.
//
// This is a REGRESSION suite for the training scenarios, not a security test:
// it drives the real UI to reach every module and asserts each vulnerable
// screen still loads. Per-module tests under integration_test/modules/ assert
// specific insecure behavior remains present, so an accidental "fix" that would
// break a lab fails CI here.
//
// Run on a device/emulator:
//   flutter test integration_test
//   flutter test integration_test/app_test.dart

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:provider/provider.dart';

import 'package:dvma/app_config.dart';
import 'package:dvma/core/module_router.dart';
import 'package:dvma/core/theme/theme_controller.dart';
import 'package:dvma/main.dart';
import 'package:dvma/vulnerability_registry.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  const config = AppConfig(
    flavor: 'ci',
    enableAll: true,
    verboseLogging: false,
    enabledCategories: {},
    disabledVulns: {},
    llmApiBase: 'http://127.0.0.1',
    insecureUpdateUrl: 'http://127.0.0.1/update',
    captureBase: 'http://127.0.0.1',
    appId: 'com.dvma',
    platform: 'android',
  );

  group('DVMA master suite', () {
    testWidgets('home surfaces the full catalog under enableAll', (
      tester,
    ) async {
      await tester.pumpWidget(
        DvmaApp(config: config, theme: ThemeController()),
      );
      await tester.pumpAndSettle();

      expect(
        find.textContaining('Authorized training use only'),
        findsOneWidget,
      );
      // Every vulnerability has a screen registered in the router.
      for (final v in VulnerabilityRegistry.all) {
        expect(
          ModuleRouter.registeredIds.contains(v.id),
          isTrue,
          reason: 'No screen registered for ${v.id}',
        );
      }
    });

    testWidgets('every enabled module screen builds without throwing', (
      tester,
    ) async {
      for (final entry in VulnerabilityRegistry.enabledFor(config)) {
        final builder = ModuleRouter.screenFor(entry.id);
        await tester.pumpWidget(
          Provider<AppConfig>.value(
            value: config,
            child: MaterialApp(home: Builder(builder: builder)),
          ),
        );
        await tester.pump(const Duration(milliseconds: 50));
        expect(
          tester.takeException(),
          isNull,
          reason: 'Screen ${entry.id} threw while building',
        );
      }
    });
  });
}
