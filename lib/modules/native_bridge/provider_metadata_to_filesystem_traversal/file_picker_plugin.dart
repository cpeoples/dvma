/// Provider-Controlled Metadata -> Plugin Filesystem Traversal helper.
///
/// INTENTIONALLY VULNERABLE (CWE-22 / CWE-73 / CWE-20): a framework/plugin
/// layer reads DISPLAY_NAME from an UNTRUSTED ContentProvider (via
/// ContentResolver.query()) and uses it DIRECTLY in filesystem path
/// construction with no sanitization. A malicious provider returns a `../`
/// display name, so the plugin writes/reads OUTSIDE its intended cache dir -
/// e.g. clobbering the app's shared_prefs (the Flutter file_picker
/// CVE-2026-38093 class).
///
/// The important angle is the PLUGIN BOUNDARY: the app calls an innocent-looking
/// `pick()` / `pickAndCache(provider)`, while the DANGEROUS unsanitized join
/// lives in the plugin layer, out of the app author's sight.
///
/// The cache write is now a real `dart:io` op: [FilePickerPlugin] resolves a
/// real, per-instance app-private base dir, seeds the app's secrets file on
/// disk OUTSIDE the plugin cache, then does `File(cacheRoot, displayName)`
/// (unsanitized) and writes the provider bytes there - so a `../` display name
/// clobbers the real secrets file on disk (adb-pullable). Under `flutter test`
/// (or when no platform dir is available) it falls back to an in-memory map so
/// the demo stays offline and deterministic. The secure [pickAndCacheSafe]
/// takes the basename / canonicalizes and confines the result under the cache
/// root.
library;

import 'dart:io';

import '../../../core/evidence_sink.dart';

/// An untrusted ContentProvider supplying a display name + file bytes.
///
/// A real ContentResolver.query() returns whatever the provider app chose for
/// `OpenableColumns.DISPLAY_NAME`; a malicious provider returns a traversal
/// path here.
class ContentProvider {
  const ContentProvider({required this.displayName, required this.bytes});

  /// The DISPLAY_NAME the provider returns - attacker-controlled.
  final String displayName;

  /// The file bytes the provider streams.
  final String bytes;

  /// An honest provider returning a benign filename.
  static const ContentProvider benign = ContentProvider(
    displayName: 'photo.jpg',
    bytes: 'JPEGDATA',
  );

  /// A MALICIOUS provider returning a `../` display name that escapes the
  /// plugin cache and lands on the app's shared_prefs secrets file.
  static const ContentProvider malicious = ContentProvider(
    displayName: '../../shared_prefs/secrets.xml',
    bytes: '<map><string name="pwned">yes</string></map>',
  );
}

/// The outcome of a pick-and-cache operation.
class PickResult {
  const PickResult({
    required this.displayName,
    required this.resolvedPath,
    required this.wrote,
    required this.escapedCacheRoot,
    this.readBack,
    this.blocked = false,
    this.reason,
  });

  /// The (untrusted) display name the provider supplied.
  final String displayName;

  /// The absolute path the plugin resolved to.
  final String resolvedPath;

  /// Whether bytes were written.
  final bool wrote;

  /// True when the write landed OUTSIDE the plugin cache root - the traversal
  /// hit.
  final bool escapedCacheRoot;

  /// The contents now at [resolvedPath] (for evidence).
  final String? readBack;

  /// Whether the safe path refused.
  final bool blocked;

  /// Why the safe path refused / a note about the write.
  final String? reason;
}

/// A real-filesystem-backed model of a file-picker plugin with a cache root.
class FilePickerPlugin {
  FilePickerPlugin._(this._baseDir, this._useRealFs);

  /// In-memory fallback (absolute-path keyed) used under test.
  final Map<String, String> _files = {};

  /// The resolved base dir (real path, or lexical [appRoot] under test).
  final String _baseDir;

  /// Whether real `dart:io` writes are available on this host.
  final bool _useRealFs;

  /// Lexical app-private storage root (evidence display / test fallback).
  static const String appRoot = '/data/data/com.dvma';

  /// The plugin's intended cache directory for picked files (relative to base).
  static const String cacheSubdir = 'cache/file_picker';

  /// A sensitive app file living OUTSIDE the plugin cache (relative to base).
  static const String secretsSubpath = 'shared_prefs/secrets.xml';

  /// The original secrets (so a test sees them get clobbered).
  static const String originalSecrets =
      '<map><string name="auth_token">SECRET-1a2b</string></map>';

  /// Lexical cache root for evidence display / the containment verdict.
  static String get cacheRoot => '$appRoot/$cacheSubdir';

  /// Lexical absolute path of the secrets file (evidence display).
  static String get secretsPath => '$appRoot/$secretsSubpath';

  /// The cache root for THIS instance (absolute, on the resolved base dir).
  String get instanceCacheRoot => '$_baseDir/$cacheSubdir';

  /// The secrets path for THIS instance (absolute, on the resolved base dir).
  String get instanceSecretsPath => '$_baseDir/$secretsSubpath';

  /// Resolves a real, unique app-private base dir. On Android this is the
  /// external files dir (adb-pullable); otherwise the app documents dir.
  /// Returns null under test / when no platform dir is available.
  static Future<String?> _resolveBaseDir(String tag) async {
    final base = await DvmaEvidence.writableBaseDir();
    return base == null ? null : '${base.path}/file_picker_$tag';
  }

  /// Creates a seeded plugin whose secrets file already exists (on disk when
  /// available, else in the in-memory fallback). [tag] keeps the vulnerable and
  /// secure instances writing to independent real dirs.
  static Future<FilePickerPlugin> seeded({String tag = 'vuln'}) async {
    final real = await _resolveBaseDir(tag);
    final base = real ?? appRoot;
    final plugin = FilePickerPlugin._(base, real != null);
    await plugin._writeRaw('$base/$secretsSubpath', originalSecrets);
    await plugin._writeRaw('$base/$cacheSubdir/.keep', '');
    return plugin;
  }

  /// The contents currently stored at [path] (for evidence / assertions).
  Future<String?> fileAt(String path) async {
    if (_useRealFs) {
      try {
        final file = File(path);
        if (await file.exists()) return await file.readAsString();
      } catch (_) {
        // Fall through to the in-memory fallback.
      }
    }
    return _files[path];
  }

  /// Real (or in-memory) write of [bytes] to the absolute [path].
  Future<void> _writeRaw(String path, String bytes) async {
    if (_useRealFs) {
      try {
        final file = File(path);
        await file.parent.create(recursive: true);
        await file.writeAsString(bytes, flush: true);
        return;
      } catch (_) {
        // Fall through to the in-memory fallback.
      }
    }
    _files[path] = bytes;
  }

  /// Naive lexical join collapsing `.`/`..` with no confinement - matches how
  /// a bare `File(cacheRoot, displayName)` normalizes on disk.
  static String _join(String base, String relative) {
    final segments = <String>[];
    for (final seg in '$base/$relative'.split('/')) {
      if (seg.isEmpty || seg == '.') continue;
      if (seg == '..') {
        if (segments.isNotEmpty) segments.removeLast();
      } else {
        segments.add(seg);
      }
    }
    return '/${segments.join('/')}';
  }

  static bool _within(String path, String root) =>
      path == root || path.startsWith('$root/');

  /// The path the vulnerable plugin lands on (for evidence display).
  static String resolvedPathFor(String displayName) =>
      _join(cacheRoot, displayName);

  /// VULN (plugin layer): the app calls this innocent-looking API; the plugin
  /// joins the PROVIDER-SUPPLIED display name to the cache root with no
  /// sanitization and WRITES it to the real filesystem, so a `../` name
  /// traverses out and clobbers app files on disk.
  Future<PickResult> pickAndCache(ContentProvider provider) async {
    final resolved = _join(instanceCacheRoot, provider.displayName);
    await _writeRaw(resolved, provider.bytes); // clobbers on disk.
    final readBack = await fileAt(resolved);

    // Mirror the clobbering write to the evidence sink (fire-and-forget).
    DvmaEvidence.record(
      'provider_metadata_to_filesystem_traversal',
      'path-traversal',
      'wrote: $resolved\n${provider.bytes}',
    );

    return PickResult(
      displayName: provider.displayName,
      resolvedPath: resolved,
      wrote: true,
      escapedCacheRoot: !_within(resolved, instanceCacheRoot),
      readBack: readBack,
      reason: 'plugin joined provider display name with no sanitization',
    );
  }

  /// SECURE contrast: the plugin strips directory components (basename),
  /// rejects traversal, and confirms the canonical result stays under the
  /// cache root before writing. Traversal is refused; files outside the cache
  /// are left intact.
  Future<PickResult> pickAndCacheSafe(ContentProvider provider) async {
    final displayName = provider.displayName;
    final basename = displayName.split('/').last.split(r'\').last;
    if (basename.isEmpty ||
        basename == '.' ||
        basename == '..' ||
        displayName.contains('..') ||
        displayName.contains('/') ||
        displayName.contains(r'\')) {
      return PickResult(
        displayName: displayName,
        resolvedPath: instanceCacheRoot,
        wrote: false,
        escapedCacheRoot: false,
        blocked: true,
        reason:
            'provider display name "$displayName" contains path '
            'separators / traversal',
      );
    }
    final resolved = _join(instanceCacheRoot, basename);
    if (!_within(resolved, instanceCacheRoot)) {
      return PickResult(
        displayName: displayName,
        resolvedPath: resolved,
        wrote: false,
        escapedCacheRoot: false,
        blocked: true,
        reason: 'resolved path escapes cache root $instanceCacheRoot',
      );
    }
    await _writeRaw(resolved, provider.bytes);
    final readBack = await fileAt(resolved);
    return PickResult(
      displayName: displayName,
      resolvedPath: resolved,
      wrote: true,
      escapedCacheRoot: false,
      readBack: readBack,
      reason: 'confined to cache root',
    );
  }
}
