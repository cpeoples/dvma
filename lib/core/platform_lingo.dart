/// Platform-aware phrasing for vulnerability demo UI text.
///
/// DVMA builds to both Android and iOS from one codebase, and many *shared*
/// modules described the insecure mechanism using Android-only terms (APK,
/// `adb`, `SharedPreferences`, `jadx`, ...). Those read as wrong on iOS. This
/// helper resolves the correct wording for the running platform so a single
/// call site renders "SharedPreferences" on Android and "UserDefaults" on iOS,
/// etc. It is intentionally tiny and dependency-free: it reads the live OS via
/// [AppConfig.detectPlatform] (honoring the `DVMA_PLATFORM` override), so demo
/// screens can call it without threading `BuildContext`/providers through.
///
/// Prefer these over hard-coded Android strings in any module whose registry
/// entry is shared (no `platforms:`) or iOS-only.
library;

import '../app_config.dart';

/// OS-specific phrasing for the insecure-mechanism strings that used to be
/// hard-coded to Android. All getters resolve against the running platform.
class PlatformLingo {
  const PlatformLingo._(this.isIOS);

  /// Build a lingo bound to the live platform (honors `DVMA_PLATFORM`).
  factory PlatformLingo.current() =>
      PlatformLingo._(AppConfig.detectPlatform() == 'ios');

  /// Build a lingo bound to an explicit platform string (`'ios'`/`'android'`),
  /// e.g. when a caller already holds `AppConfig.platform`.
  factory PlatformLingo.of(String platform) =>
      PlatformLingo._(platform == 'ios');

  final bool isIOS;

  /// Pick the iOS or Android variant.
  String pick({required String ios, required String android}) =>
      isIOS ? ios : android;

  /// The local key-value store a Flutter app persists small values to.
  /// Android: SharedPreferences (backed by an XML file). iOS: UserDefaults
  /// (backed by a plist).
  String get keyValueStore =>
      pick(ios: 'UserDefaults', android: 'SharedPreferences');

  /// The on-disk backing file for [keyValueStore].
  String get keyValueBackingFile =>
      pick(ios: 'UserDefaults plist', android: 'SharedPreferences XML');

  /// A representative on-device backing path for the local key-value store,
  /// suitable for showing in evidence. Android: the app's shared_prefs XML;
  /// iOS: the app Library/Preferences plist.
  String get keyValueBackingPath => pick(
    ios: 'Library/Preferences/<bundle-id>.plist',
    android: '/data/data/<pkg>/shared_prefs/FlutterSharedPreferences.xml',
  );

  /// Short parenthetical describing how the local store's backing file is
  /// recovered. Android: adb/root-readable; iOS: from an unencrypted backup or,
  /// on a jailbroken device (e.g. Dopamine), over SSH/SCP or with Filza.
  String get backingReadableParenthetical => pick(
    ios:
        '(readable from an unencrypted backup or a jailbroken device via '
        'SSH/SCP / Filza)',
    android: '(adb/root-readable)',
  );

  /// The tool that sweeps a full device/app backup.
  String get backupTool =>
      pick(ios: 'a Finder/iTunes backup (iMazing)', android: 'adb backup');

  /// The primary local extraction path an attacker uses to pull app files.
  /// Android: `adb` on a debuggable build, or root (Magisk) on any build. iOS:
  /// an unencrypted device backup, or a jailbroken device where the sandbox is
  /// reachable over SSH/SCP (or Filza).
  String get pullTool => pick(
    ios: 'an unencrypted backup or SSH/SCP (Filza) on a jailbroken device',
    android: 'adb (debuggable build) or a rooted device (Magisk)',
  );

  /// Short parenthetical describing recoverability of an on-device artifact.
  String get pullParenthetical => pick(
    ios:
        '(recoverable from an unencrypted backup, or over SSH/SCP / Filza '
        'on a jailbroken device)',
    android: '(adb-pullable on a debuggable build, or via root on any build)',
  );

  /// Bare adjective form of [pullParenthetical] (no parentheses). Android uses
  /// the familiar `adb-pullable`; iOS names the real recovery path since there
  /// is no single "pull" verb (backup extraction, or SSH/SCP / Filza on a
  /// jailbroken device such as one running Dopamine).
  String get pullable => pick(
    ios: 'backup- or jailbreak-readable (SSH/SCP, Filza)',
    android: 'adb-pullable',
  );

  /// The go-to tools for reading a shipped binary's symbols/strings.
  /// Android: jadx/strings. iOS: class-dump/nm/strings.
  String get reverseTools =>
      pick(ios: 'class-dump/nm/strings', android: 'jadx/strings');

  /// A single decompiler/inspection tool name to pair with `strings`.
  /// Android: jadx. iOS: class-dump.
  String get binaryInspectTool => pick(ios: 'class-dump', android: 'jadx');

  /// The compiled application artifact.
  /// Android: APK. iOS: the .app / IPA.
  String get appArtifact => pick(ios: 'app binary', android: 'APK');

  /// The distributable app package file extension. Android: apk. iOS: ipa.
  String get appPackageExt => pick(ios: 'ipa', android: 'apk');

  /// The system log channel and a tool to read it.
  String get systemLog => pick(
    ios: 'the system log (idevicesyslog)',
    android: 'Logcat (adb logcat)',
  );

  /// The name of the system log destination writes land in.
  String get logSink => pick(ios: 'the unified system log', android: 'Logcat');

  /// The tool(s) used to read the system log off-device.
  String get logReadTool => pick(
    ios: '`idevicesyslog` or Console.app',
    android: '`adb logcat` or READ_LOGS',
  );

  /// Where app permissions/entitlements are declared.
  String get permissionManifest =>
      pick(ios: 'Info.plist', android: 'AndroidManifest.xml');

  /// A generic "the running app's code-signing identity" phrase.
  String get codeSignIdentity =>
      pick(ios: 'code signature', android: 'APK signing certificate');

  /// Parenthetical naming how a local on-device artifact is extracted, used as
  /// the label suffix of [DeviceArtifactPanel]. Android: `(adb/objection)`.
  /// iOS: `(backup / jailbreak SSH)`, an unencrypted backup, or SSH/SCP (Filza)
  /// on a jailbroken device.
  String get extractionParenthetical =>
      pick(ios: '(backup / jailbreak SSH)', android: '(adb/objection)');
}
