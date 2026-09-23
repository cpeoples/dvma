import 'dart:io';

import '../../../core/evidence_sink.dart';

/// Real-filesystem model of an over-broad FileProvider / content resolver.
///
/// INTENTIONALLY VULNERABLE (CWE-22 / CWE-926): a "content resolver" resolves an
/// attacker-supplied relative path against the app-private directory WITHOUT
/// canonicalizing or confining it. A traversal path (`../../`) therefore escapes
/// the intended shared sub-directory and returns arbitrary app-private files
/// (session tokens, other users' data). This models an Android FileProvider
/// declared with an over-broad `<root-path>`/`grantUriPermissions` so another
/// app can read files outside the intended export dir.
///
/// The resolver now performs a real `dart:io` read: it seeds actual files under
/// a real app-private base dir (a benign shared file plus a session token that
/// lives OUTSIDE `shared/`), then reads `File('$base/shared/$requested')`
/// WITHOUT confinement, so a `../` request reads the token file off the real
/// disk. Under `flutter test` (or when no platform dir is available) it falls
/// back to an in-memory map so the demo stays offline and deterministic.
///
/// The vulnerable [resolve] allows traversal; [secureResolve] canonicalizes and
/// confines the request to the allowed shared directory.
class VirtualFile {
  const VirtualFile(this.path, this.contents);
  final String path;
  final String contents;
}

class FileProviderModel {
  FileProviderModel._();

  /// The intended shared export sub-directory (relative to the base dir). Only
  /// files under here are meant to be exported to other apps.
  static const String sharedDir = 'shared';

  /// Relative layout of the seeded app-private files (relative to the resolved
  /// base dir). The token + other-user notes live OUTSIDE `shared/`.
  static const Map<String, String> _seed = {
    'shared/report.pdf': 'quarterly report (public)',
    'session.token': 'auth_token=eyJhbGciOiJIUzI1NiJ9.SECRET-SESSION',
    'other_user/notes.txt': "bob's private notes: SSN 555-11-0000",
  };

  /// In-memory fallback (absolute-path keyed) used under test.
  static final Map<String, String> _memoryFs = {};

  /// Cached resolved base dir for the demo's app-private storage.
  static String? _baseDir;

  /// Resolves a real app-private base dir. On Android this is the external
  /// files dir (adb-pullable); otherwise the app documents dir. Returns null
  /// under test / when no platform dir is available.
  static Future<String?> _resolveBaseDir() async {
    final base = await DvmaEvidence.writableBaseDir();
    return base == null ? null : '${base.path}/fileprovider_demo';
  }

  /// Lexical base used for evidence display when no real dir is available.
  static const String lexicalRoot = '/data/data/com.dvma/files';

  /// Collapses `.`/`..` segments the way a naive concatenation + normalize
  /// would, WITHOUT confining the result to [sharedDir].
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

  /// Seeds the real (or in-memory) file system with the app-private files and
  /// returns the resolved base dir (real path or the lexical root under test).
  static Future<String> _ensureSeeded() async {
    if (_baseDir != null) return _baseDir!;
    final real = await _resolveBaseDir();
    final base = real ?? lexicalRoot;
    for (final entry in _seed.entries) {
      final abs = '$base/${entry.key}';
      if (real != null) {
        try {
          final file = File(abs);
          await file.parent.create(recursive: true);
          await file.writeAsString(entry.value, flush: true);
          continue;
        } catch (_) {
          // Fall through to memory fallback for this file.
        }
      }
      _memoryFs[abs] = entry.value;
    }
    _baseDir = base;
    return base;
  }

  /// The absolute path the vulnerable resolver lands on (for evidence display).
  static Future<String> resolvedPath(String requestedPath) async {
    final base = await _ensureSeeded();
    return _join('$base/$sharedDir', requestedPath);
  }

  /// VULN: resolves [requestedPath] relative to the shared export dir but never
  /// checks that the canonical result stays inside it, then performs a real
  /// file read at that path, so `../` escapes and reads app-private files off
  /// disk. Falls back to the in-memory map under test.
  static Future<String?> resolve(String requestedPath) async {
    final base = await _ensureSeeded();
    final resolved = _join('$base/$sharedDir', requestedPath);
    // No confinement check -> traversal succeeds.
    String? contents;
    try {
      final file = File(resolved);
      if (await file.exists()) contents = await file.readAsString();
    } catch (_) {
      // Fall through to the in-memory fallback.
    }
    contents ??= _memoryFs[resolved];

    if (contents != null) {
      // Mirror the leaked file to the evidence sink (fire-and-forget).
      DvmaEvidence.record(
        'fileprovider_path_traversal',
        'path-traversal',
        'wrote: $resolved\n$contents',
      );
    }
    return contents;
  }

  /// SECURE contrast: canonicalize, then confirm the result is still inside the
  /// allowed shared directory before serving it (no read on escape).
  static Future<String?> secureResolve(String requestedPath) async {
    final base = await _ensureSeeded();
    final resolved = _join('$base/$sharedDir', requestedPath);
    final allowedPrefix = '$base/$sharedDir/';
    if (!resolved.startsWith(allowedPrefix)) {
      return null; // rejected: outside the export dir
    }
    try {
      final file = File(resolved);
      if (await file.exists()) return await file.readAsString();
    } catch (_) {
      // Fall through to the in-memory fallback.
    }
    return _memoryFs[resolved];
  }

  /// Test/demo helper to reset seeded state + in-memory fallback.
  static void resetMemoryFs() {
    _memoryFs.clear();
    _baseDir = null;
  }
}
