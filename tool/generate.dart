// DVMA code generator.
//
// Reads the single source of truth (config/registry/, assembled from
// meta.yaml + categories/<id>.yaml) and
// generates:
//
//   1. lib/vulnerability_registry.dart  -- the typed catalog the app consumes.
//   2. lib/modules/<category>/<id>/<id>_screen.dart  -- a screen STUB for any
//      leaf module that does not yet have one (never overwrites existing,
//      hand-authored vulnerable screens).
//   3. docs/vulnerabilities/<id>.md  -- a doc STUB for any vuln missing one.
//
// Run from the repo root:
//
//   dart run tool/generate.dart
//
// The generated registry is committed so the app builds without a codegen
// step; re-run this whenever you add/edit entries in the YAML.

import 'dart:io';

import 'package:yaml/yaml.dart';

const _registryDir = 'config/registry';
const _registryOut = 'lib/vulnerability_registry.dart';

void main(List<String> args) {
  final root = Directory.current;
  final metaFile = File('${root.path}/$_registryDir/meta.yaml');
  if (!metaFile.existsSync()) {
    stderr.writeln(
      'ERROR: $_registryDir/meta.yaml not found. Run from the repo root.',
    );
    exitCode = 1;
    return;
  }

  // The registry is split into per-category files under
  // config/registry/categories/, with the canonical order in meta.yaml. A
  // category may be a single `<id>.yaml`, OR a directory `<id>/` of numbered
  // `*.yaml` shards (used when one category has grown large, e.g. platform);
  // the shards are merged in sorted filename order and their `vulnerabilities`
  // concatenated. We assemble everything here into the single logical
  // `categories` map the rest of the generator expects, so nothing downstream
  // changes.
  final meta = loadYaml(metaFile.readAsStringSync()) as YamlMap;
  final order = (meta['category_order'] as YamlList).cast<String>();
  final categories = <String, Map>{};
  for (final catId in order) {
    final dir = Directory('${root.path}/$_registryDir/categories/$catId');
    final file = File('${root.path}/$_registryDir/categories/$catId.yaml');
    if (dir.existsSync()) {
      final shards =
          dir
              .listSync()
              .whereType<File>()
              .where((f) => f.path.endsWith('.yaml'))
              .toList()
            ..sort((a, b) => a.path.compareTo(b.path));
      if (shards.isEmpty) {
        stderr.writeln('ERROR: category dir "$catId" has no *.yaml shards');
        exitCode = 1;
        return;
      }
      Map? merged;
      final vulns = [];
      for (final shard in shards) {
        final shardDoc = loadYaml(shard.readAsStringSync()) as YamlMap;
        final shardCat = shardDoc[catId];
        if (shardCat is! YamlMap) {
          final keys = shardDoc.keys.join(', ');
          stderr.writeln(
            'ERROR: shard "${shard.path}" must have a top-level "$catId:" key '
            '(found: $keys). A mismatched/misspelled category key is silently '
            'dropped otherwise.',
          );
          exitCode = 1;
          return;
        }
        merged ??= Map.of(shardCat);
        vulns.addAll((shardCat['vulnerabilities'] as YamlList?) ?? const []);
      }
      merged!['vulnerabilities'] = vulns;
      categories[catId] = merged;
    } else if (file.existsSync()) {
      final catDoc = loadYaml(file.readAsStringSync()) as YamlMap;
      final catBody = catDoc[catId];
      if (catBody is! YamlMap) {
        final keys = catDoc.keys.join(', ');
        stderr.writeln(
          'ERROR: "$_registryDir/categories/$catId.yaml" must have a top-level '
          '"$catId:" key (found: $keys). A mismatched/misspelled category key '
          'is silently dropped otherwise.',
        );
        exitCode = 1;
        return;
      }
      categories[catId] = catBody;
    } else {
      stderr.writeln(
        'ERROR: category "$catId" not found at '
        '$_registryDir/categories/$catId.yaml or $catId/',
      );
      exitCode = 1;
      return;
    }
  }

  final entries = <_Vuln>[];
  final cats = <_Category>[];
  final seenIds = <String, String>{};

  for (final catId in categories.keys) {
    final cat = categories[catId]!;
    cats.add(
      _Category(
        id: catId,
        title: cat['title'] as String,
        owaspMobile: (cat['owasp_mobile'] ?? '') as String,
        description: _oneLine((cat['description'] ?? '') as String),
      ),
    );
    final vulns = (cat['vulnerabilities'] as List?) ?? const [];
    for (final v in vulns) {
      final vm = v as YamlMap;
      _validateEntry(catId, vm, seenIds);
      entries.add(_Vuln.fromYaml(catId, vm));
    }
  }

  if (exitCode != 0) {
    stderr.writeln(
      'Registry validation failed. Fix the errors above and re-run.',
    );
    return;
  }

  // Canonical display order = category order (from meta.yaml), then within each
  // category by difficulty (easy -> medium -> hard) then id. This is the single
  // source of order for the app list, router, and manifest; it matches the docs
  // (.hugo/scripts/build_docs.py), so YAML source order inside a shard no longer
  // matters -- append a module anywhere and it sorts into place.
  final catRank = {for (var i = 0; i < cats.length; i++) cats[i].id: i};
  entries.sort((a, b) {
    final byCat = catRank[a.category]!.compareTo(catRank[b.category]!);
    if (byCat != 0) return byCat;
    final byDiff = _difficultyRank(a.difficulty)
        .compareTo(_difficultyRank(b.difficulty));
    if (byDiff != 0) return byDiff;
    return a.id.compareTo(b.id);
  });

  _writeRegistry(root, cats, entries);
  _writeRouter(root, entries);
  _writeAutomationManifest(root, cats, entries);
  var stubbedScreens = 0;
  var stubbedDocs = 0;
  for (final v in entries) {
    if (_writeScreenStub(root, v)) stubbedScreens++;
    if (_writeDocStub(root, v)) stubbedDocs++;
  }

  // Format the generated Dart so its output is byte-identical to what
  // `dart format` (the pre-commit hook) produces; otherwise the format hook and
  // the generator-drift hook would fight each other.
  _formatDart(root, [_registryOut, _routerOut]);

  stdout.writeln(
    'Generated $_registryOut '
    '(${entries.length} vulns across ${cats.length} categories).',
  );
  stdout.writeln(
    'Scaffolded $stubbedScreens new screen stub(s), '
    '$stubbedDocs new doc stub(s).',
  );
  final withManual = entries.where((v) => v.manualTest != null).length;
  stdout.writeln(
    'Manual-test steps: $withManual/${entries.length} modules '
    '(${entries.length - withManual} proven in-app only).',
  );

  _syncReadmeCounts(root, entries.length);
}

/// Keeps the README's module count in sync with the registry so the count
/// badge and prose never drift. Updates the module-count shields.io badge and
/// the "ships N intentionally-vulnerable modules" prose. The drift gate
/// (`git diff` after generation) then catches a stale README.
void _syncReadmeCounts(Directory root, int moduleCount) {
  final readme = File('${root.path}/README.md');
  if (!readme.existsSync()) return;
  final text = readme.readAsStringSync();
  final updated = text
      .replaceAll(
        RegExp(r'badge/Modules-\d+-blue'),
        'badge/Modules-$moduleCount-blue',
      )
      .replaceAll(
        RegExp(r'ships \*\*\d+ intentionally-vulnerable modules\*\*'),
        'ships **$moduleCount intentionally-vulnerable modules**',
      );
  if (updated != text) {
    readme.writeAsStringSync(updated);
    stdout.writeln('Synced README module count to $moduleCount.');
  }
}

/// Runs `dart format` on generated files so codegen output matches the
/// formatter. Warns (does not fail) if the SDK's `dart` is not on PATH, since
/// the surrounding CI/pre-commit format hook still enforces it.
void _formatDart(Directory root, List<String> relPaths) {
  final paths = relPaths.map((p) => '${root.path}/$p').toList();
  final result = Process.runSync('dart', ['format', ...paths]);
  if (result.exitCode != 0) {
    stderr.writeln(
      'WARN: dart format on generated files failed '
      '(${result.stderr}); the format hook will catch this.',
    );
  }
}

/// Module fields the registry understands. A key outside this set is almost
/// always a typo (e.g. `platfroms:`), which would otherwise be silently
/// dropped, so it is a hard error. Keep in sync with `_Vuln.fromYaml` and the
/// docs builder (`.hugo/scripts/build_docs.py`).
const _knownModuleKeys = {
  'id',
  'title',
  'difficulty',
  'severity',
  'masvs',
  'maswe',
  'cwe',
  'owasp_mobile',
  'owasp_llm',
  'owasp_agentic',
  'mastg_v2',
  'mastg_demo',
  'summary',
  'detail',
  'display_tags',
  'tools',
  'tools_android',
  'tools_ios',
  'attack_inputs',
  'platforms',
  'platform_note',
  'manual_test',
  'references',
  'real_demo',
};

const _difficulties = {'easy', 'medium', 'hard'};
const _severities = {'low', 'medium', 'high', 'critical'};

final _cwePattern = RegExp(r'^CWE-\d+$');
final _maswePattern = RegExp(r'^MASWE-\d+$');
final _masvsPattern = RegExp(r'^MASVS-[A-Z]+-\d+$');
final _owaspMobilePattern = RegExp(r'^M\d+$');

/// Structural validation that runs before parsing an entry into a [_Vuln].
/// Catches the mistakes a contributor is most likely to make and that the
/// downstream parser would otherwise ignore: unknown/typo'd fields, duplicate
/// ids, bad enum values, malformed standards ids, and broken reference URLs.
/// Every failure sets a non-zero [exitCode] with an actionable message; it does
/// not throw, so one run reports every problem across the whole registry.
void _validateEntry(String category, YamlMap m, Map<String, String> seenIds) {
  final rawId = m['id'];
  final id = rawId is String ? rawId : '<missing id>';

  void err(String msg) {
    stderr.writeln('ERROR: [$category/$id] $msg');
    exitCode = 1;
  }

  if (rawId is! String || rawId.trim().isEmpty) {
    err('missing or non-string "id".');
    return;
  }
  if (!RegExp(r'^[a-z0-9_]+$').hasMatch(id)) {
    err('id must be snake_case (lowercase letters, digits, underscore).');
  }
  final prior = seenIds[id];
  if (prior != null) {
    err(
      'duplicate id (already defined in category "$prior"). '
      'Every module id must be unique across the whole registry.',
    );
  } else {
    seenIds[id] = category;
  }

  for (final key in m.keys) {
    if (!_knownModuleKeys.contains(key)) {
      err(
        'unknown field "$key". Allowed fields: '
        '${(_knownModuleKeys.toList()..sort()).join(', ')}.',
      );
    }
  }

  final difficulty = m['difficulty'];
  if (difficulty != null && !_difficulties.contains(difficulty)) {
    err(
      'difficulty "$difficulty" is invalid (allowed: '
      '${_difficulties.join(', ')}).',
    );
  }

  final severity = m['severity'];
  if (severity != null && !_severities.contains(severity)) {
    err(
      'severity "$severity" is invalid (allowed: ${_severities.join(', ')}).',
    );
  }

  void checkShape(String key, RegExp pattern, String example) {
    final value = m[key];
    if (value is YamlList) {
      for (final item in value) {
        if (item is! String || !pattern.hasMatch(item)) {
          err('$key entry "$item" is malformed (expected e.g. "$example").');
        }
      }
    }
  }

  checkShape('cwe', _cwePattern, 'CWE-327');
  checkShape('maswe', _maswePattern, 'MASWE-0007');
  checkShape('masvs', _masvsPattern, 'MASVS-CRYPTO-1');
  final owaspMobile = m['owasp_mobile'];
  if (owaspMobile is String &&
      owaspMobile.isNotEmpty &&
      !_owaspMobilePattern.hasMatch(owaspMobile)) {
    err('owasp_mobile "$owaspMobile" is malformed (expected e.g. "M10").');
  }

  final references = m['references'];
  if (references is YamlList) {
    for (final ref in references) {
      if (ref is! String || !ref.contains('|')) {
        err('reference "$ref" must be "text|https://url".');
        continue;
      }
      final url = ref.substring(ref.lastIndexOf('|') + 1).trim();
      final parsed = Uri.tryParse(url);
      if (parsed == null ||
          !parsed.hasScheme ||
          !(parsed.isScheme('http') || parsed.isScheme('https'))) {
        err('reference url "$url" is not a valid http(s) URL.');
      }
    }
  }

  void requireNonEmptyString(String key) {
    final value = m[key];
    if (value is! String || value.trim().isEmpty) {
      err('missing required non-empty "$key".');
    }
  }

  requireNonEmptyString('title');
  requireNonEmptyString('summary');
  requireNonEmptyString('detail');
}

/// Emits `automation/vuln_manifest.json` - the machine-readable list of every
/// module and its stable automation identifiers, consumed by the Appium /
/// Espresso / XCUITest suites so they can walk all modules deterministically
/// without hardcoding the list or reimplementing the id-slug rules.
void _writeAutomationManifest(
  Directory root,
  List<_Category> cats,
  List<_Vuln> entries,
) {
  final items = entries.map((v) {
    return {
      'id': v.id,
      'category': v.category,
      'title': v.title,
      'difficulty': v.difficulty,
      if (v.severity != null) 'severity': v.severity,
      'platforms': v.platforms,
      if (v.attackInputs.isNotEmpty) 'attackInputs': v.attackInputs,
      // Standards mappings (mirrors the registry). MAS 2.0 fields are only
      // present when the module has a genuine mapping (never fabricated).
      'masvs': v.masvs,
      if (v.maswe.isNotEmpty) 'maswe': v.maswe,
      if (v.mastgV2.isNotEmpty) 'mastgV2': v.mastgV2,
      if (v.mastgDemo.isNotEmpty) 'mastgDemo': v.mastgDemo,
      if (v.manualTest != null) 'manualTest': v.manualTest,
      // Mirror lib/core/test_ids.dart. Keep these in sync with DvmaTestIds.
      'rowId': 'vuln_row_${v.id}',
      'screenId': 'demo_screen_${v.id}',
    };
  }).toList();

  final manifest = {
    'generatedBy': 'tool/generate.dart',
    'note': 'Automation manifest for DVMA. IDs mirror lib/core/test_ids.dart.',
    'ids': {
      'searchField': 'dvma_search_field',
      'flavorBadge': 'dvma_flavor_badge',
      'disclaimerBanner': 'dvma_disclaimer_banner',
    },
    'categories': cats.map((c) => {'id': c.id, 'title': c.title}).toList(),
    'count': entries.length,
    'modules': items,
  };

  final dir = Directory('${root.path}/automation');
  dir.createSync(recursive: true);
  final out = File('${dir.path}/vuln_manifest.json');
  // Trailing newline so the file matches the end-of-file-fixer pre-commit hook
  // (otherwise the two would fight on every run).
  out.writeAsStringSync('${_prettyJson(manifest)}\n');
  stdout.writeln(
    'Wrote automation/vuln_manifest.json '
    '(${entries.length} modules).',
  );
}

String _prettyJson(Object? value, [int indent = 0]) {
  final pad = '  ' * indent;
  final pad1 = '  ' * (indent + 1);
  if (value is Map) {
    if (value.isEmpty) return '{}';
    final entries = value.entries
        .map(
          (e) =>
              '$pad1${_dartJsonStr(e.key.toString())}: '
              '${_prettyJson(e.value, indent + 1)}',
        )
        .join(',\n');
    return '{\n$entries\n$pad}';
  }
  if (value is List) {
    if (value.isEmpty) return '[]';
    final items = value
        .map((e) => '$pad1${_prettyJson(e, indent + 1)}')
        .join(',\n');
    return '[\n$items\n$pad]';
  }
  if (value is num || value is bool) return value.toString();
  return _dartJsonStr(value.toString());
}

String _dartJsonStr(String s) =>
    '"${s.replaceAll(r'\', r'\\').replaceAll('"', r'\"')}"';

String _oneLine(String s) =>
    s.replaceAll('\n', ' ').replaceAll(RegExp(r'\s+'), ' ').trim();

// Keep in sync with DIFFICULTY_WEIGHT in .hugo/scripts/build_docs.py.
int _difficultyRank(String d) =>
    const {'easy': 0, 'medium': 1, 'hard': 2}[d] ?? 1;

String _dartStr(String s) =>
    "'${s.replaceAll(r'\', r'\\').replaceAll("'", r"\'")}'";

String _dartList(List<String> xs) => '[${xs.map(_dartStr).join(', ')}]';

String _pascal(String snake) => snake
    .split('_')
    .where((p) => p.isNotEmpty)
    .map((p) => p[0].toUpperCase() + p.substring(1))
    .join();

class _Category {
  _Category({
    required this.id,
    required this.title,
    required this.owaspMobile,
    required this.description,
  });
  final String id;
  final String title;
  final String owaspMobile;
  final String description;
}

class _Vuln {
  _Vuln({
    required this.id,
    required this.category,
    required this.title,
    required this.difficulty,
    this.severity,
    required this.masvs,
    required this.maswe,
    required this.mastgV2,
    required this.mastgDemo,
    required this.owaspMobile,
    required this.owaspLlm,
    required this.owaspAgentic,
    required this.cwe,
    required this.tools,
    required this.toolsAndroid,
    required this.toolsIos,
    required this.attackInputs,
    required this.summary,
    required this.displayTags,
    required this.platforms,
    required this.platformNote,
    required this.manualTest,
  });

  final String id;
  final String category;
  final String title;
  final String difficulty;

  /// Optional qualitative severity (low/medium/high/critical). Null when the
  /// module does not carry a defensible rating; the standards mappings (CWE /
  /// MASWE / OWASP) remain the primary severity signal, so this is never
  /// fabricated to fill a column.
  final String? severity;
  final List<String> masvs;

  /// OWASP MASWE weakness ids (e.g. MASWE-0001). Empty when the standard
  /// has no genuine match for this module (never fabricated).
  final List<String> maswe;

  /// OWASP MASTG v2 test ids (e.g. MASTG-TEST-0287). Empty when there is no
  /// genuine v2 test match for this module (never fabricated).
  final List<String> mastgV2;

  /// OWASP MASTG demo ids (e.g. MASTG-DEMO-0002). Empty when none applies.
  final List<String> mastgDemo;

  final String owaspMobile;
  final String? owaspLlm;
  final String? owaspAgentic;
  final List<String> cwe;

  /// Tooling common to every platform the module applies to. When a platform
  /// needs extra/different tools, those go in [toolsAndroid] / [toolsIos].
  final List<String> tools;

  /// Android-only tooling (in addition to [tools]); empty when unspecified.
  final List<String> toolsAndroid;

  /// iOS-only tooling (in addition to [tools]); empty when unspecified.
  final List<String> toolsIos;

  /// Payloads/artifacts the tester AUTHORS to trigger the bug (e.g. a crafted
  /// prompt/QR/deep link). Modeled apart from [tools] because they are the
  /// exploit itself, not an installable instrument. Empty when unspecified.
  final List<String> attackInputs;

  final String summary;

  /// Curated badge labels shown on the demo screen. Defaults to
  /// cwe + masvs + owaspLlm + owaspAgentic when `display_tags` is omitted.
  final List<String> displayTags;

  /// Platforms the module applies to (`android`, `ios`). Defaults to both
  /// when `platforms` is omitted in the registry (i.e. a shared vulnerability).
  final List<String> platforms;

  /// Optional note explaining how a shared module differs per platform
  /// (e.g. addJavascriptInterface vs WKScriptMessageHandler).
  final String? platformNote;

  /// Optional external/manual verification step for the module - the check a
  /// tester runs with a tool the in-app `integration_test/` suite can't drive
  /// (MITM proxy, Frida, drozer, static analysis). Rendered into the generated
  /// Manual Testing checklist. Absent for modules fully proven in-app.
  final String? manualTest;

  factory _Vuln.fromYaml(String category, YamlMap m) {
    List<String> list(String key) =>
        ((m[key] as YamlList?) ?? YamlList()).map((e) => e.toString()).toList();
    final masvs = list('masvs');
    final cwe = list('cwe');
    final owaspLlm = m['owasp_llm'] as String?;
    final owaspAgentic = m['owasp_agentic'] as String?;
    final explicitTags = m['display_tags'] as YamlList?;
    final id = m['id'] as String;
    // Standards mapping is mandatory: every finding must carry at least one
    // MASVS control, one CWE, one MASWE weakness id, and an OWASP Mobile Top 10
    // category. This is the taxonomy the docs/dashboards/badges are built on, so
    // an untagged module is a documentation hole rather than a catalog entry.
    // (All modules currently satisfy this; the gate keeps future contributions
    // honest.) CI runs `dart run tool/generate.dart` and fails on a non-zero
    // exit, so a missing tag blocks the build.
    void requireTag(String key, List<String> values) {
      if (values.isEmpty) {
        stderr.writeln('ERROR: $id is missing required "$key" tag(s).');
        exitCode = 1;
      }
    }

    requireTag('masvs', masvs);
    requireTag('cwe', cwe);
    requireTag('maswe', list('maswe'));
    if (((m['owasp_mobile'] ?? '') as String).isEmpty) {
      stderr.writeln('ERROR: $id is missing required "owasp_mobile" tag.');
      exitCode = 1;
    }
    final platforms = list('platforms');
    const knownPlatforms = {'android', 'ios'};
    for (final p in platforms) {
      if (!knownPlatforms.contains(p)) {
        stderr.writeln(
          'ERROR: $id has unknown platform "$p" (allowed: android, ios).',
        );
        exitCode = 1;
      }
    }
    return _Vuln(
      id: id,
      category: category,
      title: m['title'] as String,
      difficulty: (m['difficulty'] ?? 'medium') as String,
      severity: m['severity'] as String?,
      masvs: masvs,
      maswe: list('maswe'),
      mastgV2: list('mastg_v2'),
      mastgDemo: list('mastg_demo'),
      owaspMobile: (m['owasp_mobile'] ?? '') as String,
      owaspLlm: owaspLlm,
      owaspAgentic: owaspAgentic,
      cwe: cwe,
      tools: list('tools'),
      toolsAndroid: list('tools_android'),
      toolsIos: list('tools_ios'),
      attackInputs: list('attack_inputs'),
      summary: _oneLine((m['summary'] ?? '') as String),
      displayTags: explicitTags != null
          ? explicitTags.map((e) => e.toString()).toList()
          : [...cwe, ...masvs, ?owaspLlm, ?owaspAgentic],
      // Empty means "shared" -> applies to every supported platform.
      platforms: platforms.isEmpty ? const ['android', 'ios'] : platforms,
      platformNote: (m['platform_note'] as String?)?.trim(),
      manualTest: (m['manual_test'] as String?)?.trim(),
    );
  }
}

void _writeRegistry(Directory root, List<_Category> cats, List<_Vuln> vulns) {
  final b = StringBuffer();
  b.writeln(
    '// GENERATED by tool/generate.dart from '
    'config/registry/ (meta.yaml + categories/). DO NOT EDIT BY HAND.',
  );
  b.writeln('// Add/edit vulnerabilities in the YAML, then re-run:');
  b.writeln('//   dart run tool/generate.dart');
  b.writeln('//');
  b.writeln('// ignore_for_file: lines_longer_than_80_chars');
  b.writeln();
  b.writeln("import 'app_config.dart';");
  b.writeln("import 'core/theme/dvma_colors.dart';");
  b.writeln();
  b.writeln('/// A single vulnerability entry in the DVMA catalog.');
  b.writeln('class VulnerabilityEntry {');
  b.writeln('  const VulnerabilityEntry({');
  b.writeln('    required this.id,');
  b.writeln('    required this.category,');
  b.writeln('    required this.title,');
  b.writeln('    required this.difficulty,');
  b.writeln('    required this.masvs,');
  b.writeln('    this.maswe = const [],');
  b.writeln('    this.mastgV2 = const [],');
  b.writeln('    this.mastgDemo = const [],');
  b.writeln('    required this.owaspMobile,');
  b.writeln('    this.owaspLlm,');
  b.writeln('    this.owaspAgentic,');
  b.writeln('    required this.cwe,');
  b.writeln('    required this.tools,');
  b.writeln('    this.toolsAndroid = const [],');
  b.writeln('    this.toolsIos = const [],');
  b.writeln('    this.attackInputs = const [],');
  b.writeln('    required this.summary,');
  b.writeln('    this.displayTags = const [],');
  b.writeln("    this.platforms = const ['android', 'ios'],");
  b.writeln('    this.platformNote,');
  b.writeln('  });');
  b.writeln();
  b.writeln('  final String id;');
  b.writeln('  final String category;');
  b.writeln('  final String title;');
  b.writeln('  final DvmaDifficulty difficulty;');
  b.writeln('  final List<String> masvs;');
  b.writeln('  final List<String> maswe;');
  b.writeln('  final List<String> mastgV2;');
  b.writeln('  final List<String> mastgDemo;');
  b.writeln('  final String owaspMobile;');
  b.writeln('  final String? owaspLlm;');
  b.writeln('  final String? owaspAgentic;');
  b.writeln('  final List<String> cwe;');
  b.writeln('  final List<String> tools;');
  b.writeln('');
  b.writeln(
    '  /// Android-only tooling in addition to [tools]; empty if none.',
  );
  b.writeln('  final List<String> toolsAndroid;');
  b.writeln('');
  b.writeln('  /// iOS-only tooling in addition to [tools]; empty if none.');
  b.writeln('  final List<String> toolsIos;');
  b.writeln('');
  b.writeln('  /// Payloads/artifacts the tester authors to trigger the bug');
  b.writeln(
    '  /// (crafted prompt/QR/deep link, malicious companion app, ...).',
  );
  b.writeln('  /// These are the exploit itself, not an installable tool.');
  b.writeln('  final List<String> attackInputs;');
  b.writeln('  final String summary;');
  b.writeln('');
  b.writeln('  /// Curated badge labels for the demo screen (cwe + masvs +');
  b.writeln(
    '  /// owaspLlm + owaspAgentic unless overridden in the registry).',
  );
  b.writeln('  final List<String> displayTags;');
  b.writeln('');
  b.writeln('  /// Platforms this module applies to (`android`, `ios`).');
  b.writeln(
    '  /// Both when unspecified in the registry (a shared vulnerability).',
  );
  b.writeln('  final List<String> platforms;');
  b.writeln('');
  b.writeln('  /// Optional note on how a shared module differs per platform.');
  b.writeln('  final String? platformNote;');
  b.writeln('}');
  b.writeln();
  b.writeln('/// A category grouping of vulnerabilities (MASVS/OWASP-Mobile).');
  b.writeln('class VulnerabilityCategory {');
  b.writeln('  const VulnerabilityCategory({');
  b.writeln('    required this.id,');
  b.writeln('    required this.title,');
  b.writeln('    required this.owaspMobile,');
  b.writeln('    required this.description,');
  b.writeln('  });');
  b.writeln('  final String id;');
  b.writeln('  final String title;');
  b.writeln('  final String owaspMobile;');
  b.writeln('  final String description;');
  b.writeln('}');
  b.writeln();
  b.writeln(
    '/// The DVMA vulnerability registry: single, append-only catalog.',
  );
  b.writeln('///');
  b.writeln(
    '/// This is generated from config/registry/ '
    '(meta.yaml + categories/).',
  );
  b.writeln('/// The active [AppConfig] flavor decides which entries are');
  b.writeln('/// surfaced in the UI via [enabledFor].');
  b.writeln('class VulnerabilityRegistry {');
  b.writeln('  VulnerabilityRegistry._();');
  b.writeln();

  // categories list
  b.writeln('  static const List<VulnerabilityCategory> categories = [');
  for (final c in cats) {
    b.writeln('    VulnerabilityCategory(');
    b.writeln('      id: ${_dartStr(c.id)},');
    b.writeln('      title: ${_dartStr(c.title)},');
    b.writeln('      owaspMobile: ${_dartStr(c.owaspMobile)},');
    b.writeln('      description: ${_dartStr(c.description)},');
    b.writeln('    ),');
  }
  b.writeln('  ];');
  b.writeln();

  // all vulns
  b.writeln('  static const List<VulnerabilityEntry> all = [');
  for (final v in vulns) {
    b.writeln('    VulnerabilityEntry(');
    b.writeln('      id: ${_dartStr(v.id)},');
    b.writeln('      category: ${_dartStr(v.category)},');
    b.writeln('      title: ${_dartStr(v.title)},');
    b.writeln('      difficulty: DvmaDifficulty.${v.difficulty},');
    b.writeln('      masvs: ${_dartList(v.masvs)},');
    if (v.maswe.isNotEmpty) {
      b.writeln('      maswe: ${_dartList(v.maswe)},');
    }
    if (v.mastgV2.isNotEmpty) {
      b.writeln('      mastgV2: ${_dartList(v.mastgV2)},');
    }
    if (v.mastgDemo.isNotEmpty) {
      b.writeln('      mastgDemo: ${_dartList(v.mastgDemo)},');
    }
    b.writeln('      owaspMobile: ${_dartStr(v.owaspMobile)},');
    b.writeln(
      v.owaspLlm == null
          ? '      owaspLlm: null,'
          : '      owaspLlm: ${_dartStr(v.owaspLlm!)},',
    );
    b.writeln(
      v.owaspAgentic == null
          ? '      owaspAgentic: null,'
          : '      owaspAgentic: ${_dartStr(v.owaspAgentic!)},',
    );
    b.writeln('      cwe: ${_dartList(v.cwe)},');
    b.writeln('      tools: ${_dartList(v.tools)},');
    if (v.toolsAndroid.isNotEmpty) {
      b.writeln('      toolsAndroid: ${_dartList(v.toolsAndroid)},');
    }
    if (v.toolsIos.isNotEmpty) {
      b.writeln('      toolsIos: ${_dartList(v.toolsIos)},');
    }
    if (v.attackInputs.isNotEmpty) {
      b.writeln('      attackInputs: ${_dartList(v.attackInputs)},');
    }
    b.writeln('      summary: ${_dartStr(v.summary)},');
    b.writeln('      displayTags: ${_dartList(v.displayTags)},');
    final isShared =
        v.platforms.length == 2 &&
        v.platforms.contains('android') &&
        v.platforms.contains('ios');
    if (!isShared) {
      b.writeln('      platforms: ${_dartList(v.platforms)},');
    }
    if (v.platformNote != null && v.platformNote!.isNotEmpty) {
      b.writeln('      platformNote: ${_dartStr(v.platformNote!)},');
    }
    b.writeln('    ),');
  }
  b.writeln('  ];');
  b.writeln();
  b.writeln('  /// Entries enabled under the active [config] flavor.');
  b.writeln(
    '  static List<VulnerabilityEntry> enabledFor(AppConfig config) =>',
  );
  b.writeln('      all');
  b.writeln('          .where((v) => config.isVulnEnabled(v.id, v.category,');
  b.writeln('              platforms: v.platforms))');
  b.writeln('          .toList();');
  b.writeln();
  b.writeln('  /// Enabled entries in [category] under the active flavor.');
  b.writeln('  static List<VulnerabilityEntry> enabledInCategory(');
  b.writeln('    AppConfig config,');
  b.writeln('    String category,');
  b.writeln('  ) =>');
  b.writeln(
    '      enabledFor(config).where((v) => v.category == category).toList();',
  );
  b.writeln();
  b.writeln('  static final Map<String, VulnerabilityEntry> _byId = {');
  b.writeln('    for (final v in all) v.id: v,');
  b.writeln('  };');
  b.writeln();
  b.writeln('  /// The entry for [id], or null if unknown.');
  b.writeln('  static VulnerabilityEntry? byId(String id) => _byId[id];');
  b.writeln('}');

  final out = File('${root.path}/$_registryOut');
  out.parent.createSync(recursive: true);
  out.writeAsStringSync(b.toString());
}

const _routerOut = 'lib/core/module_router.dart';

/// Writes the id -> screen router. Always regenerated.
void _writeRouter(Directory root, List<_Vuln> vulns) {
  final b = StringBuffer();
  b.writeln('// GENERATED by tool/generate.dart. DO NOT EDIT BY HAND.');
  b.writeln('// Maps each vulnerability id to its module screen builder.');
  b.writeln('//');
  b.writeln('// ignore_for_file: lines_longer_than_80_chars');
  b.writeln();
  b.writeln("import 'package:flutter/material.dart';");
  b.writeln();
  final screenImports = [
    for (final v in vulns)
      "import '../modules/${v.category}/${v.id}/${v.id}_screen.dart';",
  ]..sort();
  for (final line in screenImports) {
    b.writeln(line);
  }
  b.writeln();
  b.writeln('typedef ScreenBuilder = Widget Function(BuildContext context);');
  b.writeln();
  b.writeln(
    '/// Routes a vulnerability id to the widget that demonstrates it.',
  );
  b.writeln('class ModuleRouter {');
  b.writeln('  ModuleRouter._();');
  b.writeln();
  b.writeln('  static const Map<String, ScreenBuilder> _screens = {');
  for (final v in vulns) {
    final cls = '${_pascal(v.id)}Screen';
    b.writeln('    ${_dartStr(v.id)}: _build$cls,');
  }
  b.writeln('  };');
  b.writeln();
  for (final v in vulns) {
    final cls = '${_pascal(v.id)}Screen';
    b.writeln(
      '  static Widget _build$cls(BuildContext context) => const $cls();',
    );
  }
  b.writeln();
  b.writeln('  /// Returns the screen builder for [vulnId].');
  b.writeln('  static ScreenBuilder screenFor(String vulnId) =>');
  b.writeln('      _screens[vulnId] ?? _missing(vulnId);');
  b.writeln();
  b.writeln(
    '  static ScreenBuilder _missing(String vulnId) => (context) => Scaffold(',
  );
  b.writeln('        appBar: AppBar(title: const Text(\'Not found\')),');
  b.writeln(
    '        body: Center(child: Text(\'No screen registered for \$vulnId\')),',
  );
  b.writeln('      );');
  b.writeln();
  b.writeln('  /// All registered ids (used by the master integration test).');
  b.writeln(
    '  static List<String> get registeredIds => _screens.keys.toList();',
  );
  b.writeln('}');

  final out = File('${root.path}/$_routerOut');
  out.parent.createSync(recursive: true);
  out.writeAsStringSync(b.toString());
}

/// Writes a screen stub if none exists. Returns true if a file was created.
bool _writeScreenStub(Directory root, _Vuln v) {
  final dir = Directory('${root.path}/lib/modules/${v.category}/${v.id}');
  final path = '${dir.path}/${v.id}_screen.dart';
  if (File(path).existsSync()) return false;
  dir.createSync(recursive: true);
  final cls = '${_pascal(v.id)}Screen';
  final b = StringBuffer();
  b.writeln('import \'package:flutter/material.dart\';');
  b.writeln();
  b.writeln('import \'../../../core/test_ids.dart\';');
  b.writeln('import \'../../../core/theme/dvma_colors.dart\';');
  b.writeln('import \'../../../core/widgets.dart\';');
  b.writeln();
  b.writeln('/// ${v.title}');
  b.writeln('///');
  b.writeln('/// ${v.summary}');
  b.writeln('///');
  b.writeln(
    '/// STUB scaffolded by tool/generate.dart. Replace the body with a',
  );
  b.writeln(
    '/// screen that actually demonstrates the vulnerable behavior, then',
  );
  b.writeln(
    '/// keep the integration test in sync so CI catches accidental fixes.',
  );
  b.writeln('class $cls extends StatelessWidget {');
  b.writeln('  const $cls({super.key});');
  b.writeln();
  b.writeln('  static const String vulnId = ${_dartStr(v.id)};');
  b.writeln();
  b.writeln('  @override');
  b.writeln('  Widget build(BuildContext context) {');
  b.writeln('    return testId(');
  b.writeln('      DvmaTestIds.demoScreen(vulnId),');
  b.writeln('      Scaffold(');
  b.writeln('        appBar: AppBar(title: const Text(${_dartStr(v.title)})),');
  b.writeln('        body: Padding(');
  b.writeln('          padding: const EdgeInsets.all(DvmaSpacing.lg),');
  b.writeln('          child: Column(');
  b.writeln('            crossAxisAlignment: CrossAxisAlignment.start,');
  b.writeln('            children: [');
  b.writeln(
    '              DvmaBadge.difficulty(DvmaDifficulty.${v.difficulty}),',
  );
  b.writeln('              const SizedBox(height: DvmaSpacing.md),');
  b.writeln('              const Text(${_dartStr(v.summary)}),');
  b.writeln('              const SizedBox(height: DvmaSpacing.md),');
  b.writeln(
    '              const DvmaMono(\'This module has no demo yet. '
    'Wire the vulnerable action here.\'),',
  );
  b.writeln('            ],');
  b.writeln('          ),');
  b.writeln('        ),');
  b.writeln('      ),');
  b.writeln('    );');
  b.writeln('  }');
  b.writeln('}');
  File(path).writeAsStringSync(b.toString());
  return true;
}

/// Writes a doc stub if none exists. Returns true if a file was created.
bool _writeDocStub(Directory root, _Vuln v) {
  final path = '${root.path}/docs/vulnerabilities/${v.id}.md';
  if (File(path).existsSync()) return false;
  final f = File(path);
  f.parent.createSync(recursive: true);
  final b = StringBuffer();
  b.writeln('# ${v.title}');
  b.writeln();
  b.writeln('<!-- dvma:generated-stub -->');
  b.writeln(
    '> **Training only.** This is an intentional vulnerability. See the '
    'root README disclaimer.',
  );
  b.writeln();
  b.writeln('| Field | Value |');
  b.writeln('|-------|-------|');
  b.writeln('| ID | `${v.id}` |');
  b.writeln('| Category | `${v.category}` |');
  b.writeln('| Difficulty | ${v.difficulty} |');
  if (v.severity != null) {
    b.writeln('| Severity | ${v.severity} |');
  }
  b.writeln('| OWASP Mobile Top 10 (2024) | ${v.owaspMobile} |');
  if (v.owaspLlm != null) {
    b.writeln('| OWASP LLM/GenAI Top 10 (2025) | ${v.owaspLlm} |');
  }
  if (v.owaspAgentic != null) {
    b.writeln('| OWASP Agentic AI Top 10 (2025) | ${v.owaspAgentic} |');
  }
  b.writeln('| MASVS | ${v.masvs.join(", ")} |');
  if (v.maswe.isNotEmpty) {
    b.writeln('| MASWE | ${v.maswe.join(", ")} |');
  }
  if (v.mastgV2.isNotEmpty) {
    b.writeln('| MASTG (v2 tests) | ${v.mastgV2.join(", ")} |');
  }
  if (v.mastgDemo.isNotEmpty) {
    b.writeln('| MASTG demos | ${v.mastgDemo.join(", ")} |');
  }
  b.writeln('| CWE | ${v.cwe.join(", ")} |');
  b.writeln('| Suggested tools | ${v.tools.join(", ")} |');
  b.writeln();
  b.writeln('## Description');
  b.writeln();
  b.writeln(v.summary);
  b.writeln();
  b.writeln('## Reproduce in the app');
  b.writeln();
  b.writeln(
    'DVMA is the harness: open **${v.title}** (`${v.id}`) from the home '
    'index, tap the demo action, and read the on-screen evidence panel, which '
    'prints the concrete proof (leaked value, accepted replay, executed '
    'payload, or unauthorized result). Where a module provides a '
    'secure/hardened action, run it too and confirm the same attack is '
    'rejected. The published docs site renders a full step-by-step playbook for '
    'this module from the registry, including the optional on-device tooling '
    'path below.',
  );
  b.writeln();
  b.writeln('## Expected tooling');
  b.writeln();
  b.writeln(v.tools.map((t) => '- $t').join('\n'));
  b.writeln();
  b.writeln('## Standards mapping');
  b.writeln();
  b.writeln('- OWASP Mobile Top 10 (2024): ${v.owaspMobile}');
  if (v.owaspLlm != null) {
    b.writeln(
      '- OWASP Top 10 for LLM/GenAI Applications (2025): ${v.owaspLlm}',
    );
  }
  if (v.owaspAgentic != null) {
    b.writeln(
      '- OWASP Top 10 for Agentic AI Applications (2025): ${v.owaspAgentic}',
    );
  }
  b.writeln('- OWASP MASVS: ${v.masvs.join(", ")}');
  if (v.maswe.isNotEmpty) {
    b.writeln('- OWASP MASWE: ${v.maswe.join(", ")}');
  }
  if (v.mastgV2.isNotEmpty) {
    b.writeln('- OWASP MASTG (v2 tests): ${v.mastgV2.join(", ")}');
  }
  if (v.mastgDemo.isNotEmpty) {
    b.writeln('- OWASP MASTG demos: ${v.mastgDemo.join(", ")}');
  }
  b.writeln('- CWE: ${v.cwe.join(", ")}');
  f.writeAsStringSync(b.toString());
  return true;
}
