/// DVMA build-time configuration.
///
/// All configuration is centralized under `config/`. Build flavors are JSON
/// files in `config/flavors/` selected at build time via:
///
/// ```sh
/// flutter run --dart-define-from-file=config/flavors/dev.json
/// ```
///
/// The values below are read from `--dart-define` (populated by
/// `--dart-define-from-file`). [AppConfig.fromEnvironment] parses them once at
/// startup into a single immutable object; the vulnerability registry and the
/// UI consult that object to decide which vulnerabilities are enabled. There
/// are deliberately no scattered `.env` files or per-module config.
library;

import 'dart:io' show Platform;

import 'core/config/dvma_env.dart';

/// Immutable, parsed view of the active build flavor.
class AppConfig {
  const AppConfig({
    required this.flavor,
    required this.enableAll,
    required this.verboseLogging,
    required this.enabledCategories,
    required this.disabledVulns,
    required this.llmApiBase,
    required this.insecureUpdateUrl,
    required this.captureBase,
    required this.appId,
    required this.platform,
  });

  /// Flavor name: `dev`, `training`, or `full`.
  final String flavor;

  /// When true, every category is enabled regardless of [enabledCategories].
  final bool enableAll;

  /// When true, modules emit verbose (intentionally leaky) logs.
  final bool verboseLogging;

  /// Category ids enabled for this flavor.
  final Set<String> enabledCategories;

  /// Individual vulnerability ids explicitly disabled for this flavor.
  final Set<String> disabledVulns;

  /// Base URL for the in-app AI assistant's (mock) LLM backend.
  final String llmApiBase;

  /// Unauthenticated model-update URL used by the AI supply-chain demo.
  final String insecureUpdateUrl;

  /// Base URL the *real* network modules (cleartext, weak-TLS, accept-all,
  /// bypassable pinning) send genuine traffic to. Defaults to a local capture
  /// listener (`10.0.2.2` is the host loopback from the Android emulator) so
  /// real packets hit the trainee's own mitmproxy/listener and nothing leaves
  /// the local network. Override for a physical device via
  /// `--dart-define=DVMA_CAPTURE_BASE=http://<host-ip>:8080`.
  final String captureBase;

  /// The app package / bundle id (single source of truth). Native code derives
  /// this from `BuildConfig.APPLICATION_ID`; Dart receives it via the
  /// `DVMA_APP_ID` dart-define (wired in `config/flavors/*.json`) so modules
  /// build the cross-app action/permission names without hardcoding the package.
  final String appId;

  /// The platform this build is running on: `android` or `ios`. Modules whose
  /// registry `platforms` list excludes this value are hidden (hard filter), so
  /// the Android build lists only Android + shared modules and vice versa.
  final String platform;

  /// Detects the running platform, honoring [DvmaEnv]'s override first. Falls
  /// back to `android` for any non-iOS host so the catalog is never empty.
  static String detectPlatform() {
    final override = DvmaEnv.app.platformOverride;
    if (override.isNotEmpty) return override;
    return Platform.isIOS ? 'ios' : 'android';
  }

  /// Parse the active flavor from the [DvmaEnv] build-time configuration.
  factory AppConfig.fromEnvironment() {
    final gating = DvmaEnv.gating;
    final network = DvmaEnv.network;
    return AppConfig(
      flavor: DvmaEnv.app.flavor,
      enableAll: gating.enableAll,
      verboseLogging: gating.verboseLogging,
      enabledCategories: _splitCsv(gating.enabledCategories),
      disabledVulns: _splitCsv(gating.disabledVulns),
      llmApiBase: network.llmApiBase,
      insecureUpdateUrl: network.insecureUpdateUrl,
      captureBase: network.captureBase,
      appId: DvmaEnv.app.appId,
      platform: detectPlatform(),
    );
  }

  static Set<String> _splitCsv(String raw) =>
      raw.split(',').map((s) => s.trim()).where((s) => s.isNotEmpty).toSet();

  /// Whether a category is active under this flavor.
  bool isCategoryEnabled(String categoryId) =>
      enableAll || enabledCategories.contains(categoryId);

  /// Whether an individual vulnerability is active under this flavor.
  ///
  /// A vulnerability is enabled when its category is enabled, it is not in the
  /// per-flavor [disabledVulns] denylist, AND it applies to the current
  /// [platform] (shared modules apply to every platform).
  bool isVulnEnabled(
    String vulnId,
    String categoryId, {
    List<String> platforms = const ['android', 'ios'],
  }) =>
      isCategoryEnabled(categoryId) &&
      !disabledVulns.contains(vulnId) &&
      platforms.contains(platform);
}
