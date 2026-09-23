/// Shared Apple App-Site-Association (AASA) loader + component matcher.
///
/// Loads the real bundled `assets/aasa/apple-app-site-association.json`
/// (`rootBundle.loadString`), PARSES it (`jsonDecode`), and matches an
/// attacker-supplied incoming URL against the real `applinks.details[].components`
/// using Apple's actual glob semantics (`*` = any run, `?` = single char, plus
/// `exclude` and a `?`-query object). Two DVMA modules share this so their
/// associated-domain checks run on the SAME real, on-disk association file:
///  * universal_link_aasa_confusion (Universal Link routing), and
///  * app_clip_invocation_injection (App Clip invocation validation).
///
/// If the asset cannot be loaded (a host where `rootBundle` is unavailable), it
/// falls back to an embedded copy of the same JSON so the deterministic model
/// still runs offline under `flutter test`.
library;

import 'dart:convert';

import 'package:flutter/services.dart' show rootBundle;

/// One parsed `components` entry from `applinks.details[]`.
class AasaComponent {
  const AasaComponent({
    required this.path,
    required this.query,
    required this.exclude,
    required this.comment,
  });

  /// The `/` path pattern (Apple glob: `*` any run, `?` one char).
  final String path;

  /// Optional `?` query constraints (key -> value pattern).
  final Map<String, String> query;

  /// `exclude: true` entries deny a match rather than allow it.
  final bool exclude;

  /// Developer `comment` (surfaces the "overly broad" intent in evidence).
  final String comment;

  bool get isBroad => path == '/*' || path.endsWith('/*') || path.contains('*');
}

/// The parsed association: appIDs + the ordered component list for a domain.
class AasaAssociation {
  const AasaAssociation({required this.appIDs, required this.components});

  final List<String> appIDs;
  final List<AasaComponent> components;

  /// First component (in file order) that matches [path] (+ optional [query])
  /// and is not an `exclude`, or null when nothing legitimately matches.
  AasaComponent? match(String path, {Map<String, String> query = const {}}) {
    for (final c in components) {
      if (!_matchGlob(c.path, path)) continue;
      if (!_matchQuery(c.query, query)) continue;
      if (c.exclude) return null;
      return c;
    }
    return null;
  }

  /// Exact, non-wildcard match only (secure contrast): the component must match
  /// the path AND carry no `*`/`?` wildcard.
  AasaComponent? matchExact(
    String path, {
    Map<String, String> query = const {},
  }) {
    for (final c in components) {
      if (c.exclude || c.isBroad || c.path.contains('?')) continue;
      if (c.path != path) continue;
      if (!_matchQuery(c.query, query)) continue;
      return c;
    }
    return null;
  }
}

/// Apple-style glob: `*` matches any run (incl. empty), `?` matches one char.
/// Everything else is literal. Anchored at both ends.
bool _matchGlob(String pattern, String value) {
  // Iterative backtracking wildcard match (no regex catastrophes).
  var p = 0;
  var v = 0;
  var star = -1;
  var mark = 0;
  while (v < value.length) {
    if (p < pattern.length && (pattern[p] == value[v] || pattern[p] == '?')) {
      p++;
      v++;
    } else if (p < pattern.length && pattern[p] == '*') {
      star = p++;
      mark = v;
    } else if (star != -1) {
      p = star + 1;
      v = ++mark;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] == '*') {
    p++;
  }
  return p == pattern.length;
}

bool _matchQuery(Map<String, String> patterns, Map<String, String> actual) {
  for (final entry in patterns.entries) {
    final v = actual[entry.key];
    if (v == null || !_matchGlob(entry.value, v)) return false;
  }
  return true;
}

/// Loads + parses the bundled association file, matched against [domain].
class AasaLoader {
  AasaLoader._();

  /// Bundled asset path (registered under `flutter: assets:` in pubspec.yaml).
  static const String assetPath = 'assets/aasa/apple-app-site-association.json';

  static AasaAssociation? _cached;

  /// Loads the real bundled AASA JSON off the asset bundle and parses the
  /// `applinks.details[]` components. Falls back to an embedded copy if the
  /// bundle is unavailable (never throws).
  static Future<AasaAssociation> load() async {
    if (_cached != null) return _cached!;
    String raw;
    try {
      raw = await rootBundle.loadString(assetPath);
    } catch (_) {
      raw = _embedded;
    }
    _cached = _parse(raw);
    return _cached!;
  }

  /// Parses the embedded fallback association synchronously. Used by callers
  /// that must stay synchronous (e.g. under `flutter test`) while the async
  /// [load] path reads the real bundled asset on device.
  static AasaAssociation embedded() => _cachedEmbedded ??= _parse(_embedded);

  static AasaAssociation? _cachedEmbedded;

  static AasaAssociation _parse(String raw) {
    try {
      final root = jsonDecode(raw) as Map<String, dynamic>;
      final details =
          ((root['applinks'] as Map<String, dynamic>?)?['details']
              as List<dynamic>?) ??
          const [];
      final appIDs = <String>[];
      final components = <AasaComponent>[];
      for (final d in details.whereType<Map<String, dynamic>>()) {
        for (final id in (d['appIDs'] as List<dynamic>? ?? const [])) {
          appIDs.add('$id');
        }
        final legacy = d['appID'];
        if (legacy is String) appIDs.add(legacy);
        for (final c
            in (d['components'] as List<dynamic>? ?? const [])
                .whereType<Map<String, dynamic>>()) {
          final query = <String, String>{};
          final q = c['?'];
          if (q is Map<String, dynamic>) {
            q.forEach((k, v) => query[k] = '$v');
          }
          components.add(
            AasaComponent(
              path: '${c['/'] ?? ''}',
              query: query,
              exclude: c['exclude'] == true,
              comment: '${c['comment'] ?? ''}',
            ),
          );
        }
      }
      return AasaAssociation(appIDs: appIDs, components: components);
    } catch (_) {
      return const AasaAssociation(appIDs: [], components: []);
    }
  }

  /// Embedded fallback (kept in sync with the bundled asset) for hosts where
  /// the asset bundle is unavailable.
  static const String _embedded = '''
{
  "applinks": {
    "details": [
      {
        "appIDs": ["TEAMID.com.dvma.app"],
        "components": [
          { "/": "/promo/summer2026", "comment": "exact benign promo path - safe entry" },
          { "/": "/account/*", "comment": "OVERLY BROAD: matches /account/resetPassword" },
          { "/": "/*", "comment": "OVERLY BROAD catch-all" }
        ]
      }
    ]
  },
  "appclips": { "apps": ["TEAMID.com.dvma.Clip"] },
  "webcredentials": { "apps": ["TEAMID.com.dvma.app"] }
}
''';
}
