import 'package:flutter_test/flutter_test.dart';

import 'package:dvma/app_config.dart';
import 'package:dvma/core/theme/theme_controller.dart';
import 'package:dvma/main.dart';
import 'package:dvma/vulnerability_registry.dart';

void main() {
  testWidgets('DVMA home renders the disclaimer and vulnerability index', (
    WidgetTester tester,
  ) async {
    const config = AppConfig(
      flavor: 'test',
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

    await tester.pumpWidget(DvmaApp(config: config, theme: ThemeController()));
    await tester.pump();

    // The mandatory training-only disclaimer must always be visible.
    expect(find.textContaining('Authorized training use only'), findsOneWidget);

    // With enableAll, every module applicable to this platform is surfaced
    // (the hard platform filter still hides ios-only modules on android).
    final applicable = VulnerabilityRegistry.all
        .where((v) => v.platforms.contains('android'))
        .length;
    expect(VulnerabilityRegistry.enabledFor(config).length, applicable);
    expect(VulnerabilityRegistry.all.length, greaterThan(60));
  });

  test('per-platform hard filter hides the other platform\'s modules', () {
    AppConfig cfg(String platform) => AppConfig(
      flavor: 'test',
      enableAll: true,
      verboseLogging: false,
      enabledCategories: const {},
      disabledVulns: const {},
      llmApiBase: 'http://127.0.0.1',
      insecureUpdateUrl: 'http://127.0.0.1/update',
      captureBase: 'http://127.0.0.1',
      appId: 'com.dvma',
      platform: platform,
    );

    final android = VulnerabilityRegistry.enabledFor(cfg('android'));
    final ios = VulnerabilityRegistry.enabledFor(cfg('ios'));

    // An android-only module appears only on android; an ios-only only on ios.
    bool has(List<VulnerabilityEntry> xs, String id) =>
        xs.any((v) => v.id == id);
    expect(has(android, 'exported_android_components'), isTrue);
    expect(has(ios, 'exported_android_components'), isFalse);
    expect(has(ios, 'keychain_state_integrity_manipulation'), isTrue);
    expect(has(android, 'keychain_state_integrity_manipulation'), isFalse);

    // Shared modules appear on both.
    expect(has(android, 'weak_algorithms'), isTrue);
    expect(has(ios, 'weak_algorithms'), isTrue);

    // Every enabled entry actually applies to its platform.
    expect(android.every((v) => v.platforms.contains('android')), isTrue);
    expect(ios.every((v) => v.platforms.contains('ios')), isTrue);

    // Union of both platforms covers the whole catalog.
    final union = {...android.map((v) => v.id), ...ios.map((v) => v.id)};
    expect(union.length, VulnerabilityRegistry.all.length);
  });
}
