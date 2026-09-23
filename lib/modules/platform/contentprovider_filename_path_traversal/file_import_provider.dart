/// ContentProvider File-Import Filename Path Traversal helper.
///
/// INTENTIONALLY VULNERABLE (CWE-22 / CWE-73 / CWE-926): a ContentProvider /
/// file-import API takes the CALLER-SUPPLIED display name (filename) and joins
/// it under the app's import directory with no canonicalization. A `../`
/// filename therefore traverses OUT of the intended import dir and
/// overwrites/reads arbitrary app-private files - e.g. writing
/// `../../shared_prefs/secrets.xml` clobbers the app's stored secrets (the
/// Android ContentProvider import-traversal CVE-2025-65814 / CVE-2025-65815
/// class).
///
/// The import now performs a real `dart:io` write: [FileImportProvider] resolves
/// a real, per-instance app-private base dir, seeds the secrets file that lives
/// OUTSIDE the import dir on disk, then writes the imported bytes to
/// `File('$importRoot/$displayName')` WITHOUT canonicalization, so a `../` name
/// clobbers the real secrets file on disk (adb-pullable). Under `flutter test`
/// (or when no platform dir is available) it falls back to an in-memory map so
/// the demo stays offline and deterministic. The secure [importFileSafe] strips
/// path separators / canonicalizes and confines the result under the import
/// root, rejecting traversal.
library;

import 'dart:io';

import '../../../core/evidence_sink.dart';

/// The outcome of a file-import request.
class ImportResult {
  const ImportResult({
    required this.wrote,
    required this.blocked,
    required this.resolvedPath,
    this.readBack,
    this.reason,
  });

  /// Whether bytes were written to [resolvedPath].
  final bool wrote;

  /// Whether the safe importer refused (secure path).
  final bool blocked;

  /// The absolute path the request resolved to.
  final String resolvedPath;

  /// The contents now at [resolvedPath] after the import (for evidence).
  final String? readBack;

  /// Why the safe importer refused (secure path only).
  final String? reason;

  /// True when the write landed OUTSIDE the import root - the traversal hit.
  bool escapedImportRoot(String importRoot) =>
      wrote && !_within(resolvedPath, importRoot);

  static bool _within(String path, String root) =>
      path == root || path.startsWith('$root/');
}

/// A real-filesystem-backed model of a ContentProvider file-import API.
class FileImportProvider {
  FileImportProvider._(this._baseDir, this._useRealFs);

  /// In-memory fallback (absolute-path keyed) used under test.
  final Map<String, String> _files = {};

  /// The resolved base dir (real path, or the lexical [appRoot] under test).
  final String _baseDir;

  /// Whether real `dart:io` writes are available on this host.
  final bool _useRealFs;

  /// Lexical app-private storage root (evidence display / test fallback).
  static const String appRoot = '/data/data/com.dvma';

  /// The directory imported files are meant to land in (relative to base).
  static const String importSubdir = 'files/imports';

  /// The sensitive app file, relative to the base dir, that lives OUTSIDE the
  /// import dir.
  static const String secretsSubpath = 'shared_prefs/secrets.xml';

  /// The original secrets contents (so a test can see them get clobbered).
  static const String originalSecrets =
      '<map><string name="auth_token">SECRET-9f3a</string></map>';

  /// A malicious display name whose `../` escapes the import dir (imports ->
  /// files -> com.dvma) and lands on the app's secrets file.
  static const String traversalDisplayName = '../../shared_prefs/secrets.xml';

  /// A benign display name that stays in the import dir.
  static const String benignDisplayName = 'invoice.pdf';

  /// Lexical import root for evidence display / the containment verdict.
  static String get importRoot => '$appRoot/$importSubdir';

  /// Lexical absolute path of the secrets file (evidence display).
  static String get secretsPath => '$appRoot/$secretsSubpath';

  /// The import root for THIS instance (absolute, on the resolved base dir).
  String get instanceImportRoot => '$_baseDir/$importSubdir';

  /// The secrets path for THIS instance (absolute, on the resolved base dir).
  String get instanceSecretsPath => '$_baseDir/$secretsSubpath';

  /// Resolves a real, unique app-private base dir. On Android this is the
  /// external files dir (adb-pullable); otherwise the app documents dir.
  /// Returns null under test / when no platform dir is available.
  static Future<String?> _resolveBaseDir(String tag) async {
    final base = await DvmaEvidence.writableBaseDir();
    return base == null ? null : '${base.path}/contentprovider_$tag';
  }

  /// Creates a seeded provider whose secrets file already exists (on disk when
  /// available, else in the in-memory fallback). [tag] keeps the vulnerable and
  /// secure instances writing to independent real dirs.
  static Future<FileImportProvider> seeded({String tag = 'vuln'}) async {
    final real = await _resolveBaseDir(tag);
    final base = real ?? appRoot;
    final provider = FileImportProvider._(base, real != null);
    // Seed the secrets file + an import-dir marker.
    await provider._writeRaw('$base/$secretsSubpath', originalSecrets);
    await provider._writeRaw('$base/$importSubdir/.keep', '');
    return provider;
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

  /// Naive lexical join collapsing `.`/`..` with no confinement to the import
  /// root - matches how a bare `File(importRoot, displayName)` normalizes.
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

  /// The absolute path the vulnerable importer lands on (for evidence display).
  static String resolvedPathFor(String displayName) =>
      _join(importRoot, displayName);

  /// VULN: join the caller-supplied [displayName] to the import root and WRITE
  /// the bytes there on the real filesystem with no canonicalization /
  /// confinement, so `../` traverses out and overwrites arbitrary app files.
  Future<ImportResult> importFile(String displayName, String bytes) async {
    final resolved = _join(instanceImportRoot, displayName);
    await _writeRaw(resolved, bytes); // clobbers whatever lived there on disk.
    final readBack = await fileAt(resolved);

    // Mirror the clobbering write to the evidence sink (fire-and-forget).
    DvmaEvidence.record(
      'contentprovider_filename_path_traversal',
      'path-traversal',
      'wrote: $resolved\n$bytes',
    );

    return ImportResult(
      wrote: true,
      blocked: false,
      resolvedPath: resolved,
      readBack: readBack,
      reason: 'wrote with no canonicalization / confinement',
    );
  }

  /// SECURE contrast: reject path separators in the display name and confirm the
  /// canonical result stays under the import root before writing. Traversal is
  /// refused; the target file outside the root is left intact.
  Future<ImportResult> importFileSafe(String displayName, String bytes) async {
    // Confine to the basename: strip any directory components an attacker put
    // in the display name.
    final sanitized = displayName.split('/').last.split(r'\').last;
    if (sanitized.isEmpty ||
        sanitized == '.' ||
        sanitized == '..' ||
        displayName.contains('..') ||
        displayName.contains('/') ||
        displayName.contains(r'\')) {
      return ImportResult(
        wrote: false,
        blocked: true,
        resolvedPath: instanceImportRoot,
        reason:
            'display name "$displayName" contains path separators / '
            'traversal',
      );
    }
    final resolved = _join(instanceImportRoot, sanitized);
    final allowedPrefix = '$instanceImportRoot/';
    if (!resolved.startsWith(allowedPrefix)) {
      return ImportResult(
        wrote: false,
        blocked: true,
        resolvedPath: resolved,
        reason: 'resolved path escapes import root $instanceImportRoot',
      );
    }
    await _writeRaw(resolved, bytes);
    final readBack = await fileAt(resolved);
    return ImportResult(
      wrote: true,
      blocked: false,
      resolvedPath: resolved,
      readBack: readBack,
      reason: 'confined to import root',
    );
  }
}
