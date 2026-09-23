// Propagates the single-source app id from config/app.json to every build
// system that cannot read it directly (Dart flavors, the companion attacker
// app, and the iOS Xcode project).
//
// Android Gradle reads config/app.json itself at configure time, so the app's
// runtime package (BuildConfig.APPLICATION_ID + manifest ${applicationId}) is
// already single-sourced. This tool keeps the *other* build systems in sync.
//
// Usage:
//   dart run tool/sync_app_id.dart          # apply
//   dart run tool/sync_app_id.dart --check  # verify only (non-zero if drifted)
//
// Run it after editing config/app.json. It is idempotent.
import 'dart:convert';
import 'dart:io';

void main(List<String> args) {
  final check = args.contains('--check');
  final root = Directory.current;
  final appJson = File('${root.path}/config/app.json');
  if (!appJson.existsSync()) {
    stderr.writeln('config/app.json not found (run from the repo root)');
    exit(2);
  }

  final appId =
      (jsonDecode(appJson.readAsStringSync()) as Map)['app_id'] as String;
  if (appId.isEmpty) {
    stderr.writeln('config/app.json has an empty app_id');
    exit(2);
  }

  final edits = <_Edit>[
    // Dart flavors: DVMA_APP_ID forwarded to the app via --dart-define-from-file.
    for (final f in ['dev', 'training', 'full'])
      _Edit(
        'config/flavors/$f.json',
        RegExp(r'("DVMA_APP_ID"\s*:\s*")([^"]*)(")'),
        (m) => '${m[1]}$appId${m[3]}',
      ),
    // Companion attacker app: a separate app that cannot read DVMA's BuildConfig.
    _Edit(
      'companion/dvma-attacker/app/src/main/kotlin/com/dvma/attacker/Dvma.kt',
      RegExp(r'(const val PKG = ")([^"]*)(")'),
      (m) => '${m[1]}$appId${m[3]}',
    ),
    // iOS: main app bundle id. The test targets keep their own suffixed ids
    // (<appid>.RunnerTests / <appid>.RunnerUITests), so the main-app rule must
    // skip any identifier that carries a Runner*Tests suffix, and dedicated
    // rules re-derive each test id from the app id.
    _Edit(
      'ios/Runner.xcodeproj/project.pbxproj',
      RegExp(
        r'(PRODUCT_BUNDLE_IDENTIFIER = )(?!.*Runner(?:UI)?Tests)([\w.]+)(;)',
      ),
      (m) => '${m[1]}$appId${m[3]}',
    ),
    _Edit(
      'ios/Runner.xcodeproj/project.pbxproj',
      RegExp(r'(PRODUCT_BUNDLE_IDENTIFIER = )([\w.]+)(\.RunnerTests;)'),
      (m) => '${m[1]}$appId${m[3]}',
    ),
    _Edit(
      'ios/Runner.xcodeproj/project.pbxproj',
      RegExp(r'(PRODUCT_BUNDLE_IDENTIFIER = )([\w.]+)(\.RunnerUITests;)'),
      (m) => '${m[1]}$appId${m[3]}',
    ),
  ];

  var drifted = false;
  for (final edit in edits) {
    final file = File('${root.path}/${edit.path}');
    if (!file.existsSync()) {
      stderr.writeln('skip (missing): ${edit.path}');
      continue;
    }
    final before = file.readAsStringSync();
    final after = before.replaceAllMapped(edit.pattern, edit.replace);
    if (before == after) continue;
    drifted = true;
    if (check) {
      stderr.writeln('DRIFT: ${edit.path} is out of sync with config/app.json');
    } else {
      file.writeAsStringSync(after);
      stdout.writeln('synced: ${edit.path}');
    }
  }

  if (check && drifted) {
    stderr.writeln(
      'app id drift detected - run `dart run tool/sync_app_id.dart`',
    );
    exit(1);
  }
  stdout.writeln(
    check
        ? 'app id in sync ($appId)'
        : 'done - app id = $appId (Android reads config/app.json directly)',
  );
}

class _Edit {
  _Edit(this.path, this.pattern, this.replace);
  final String path;
  final RegExp pattern;
  final String Function(Match) replace;
}
