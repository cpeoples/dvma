/// Shortcuts / App-Intents path + symlink sandbox-escape helper.
///
/// INTENTIONALLY VULNERABLE (CWE-22 / CWE-59 / CWE-61): untrusted Shortcuts /
/// App-Intents input drives a file operation whose path is resolved through a
/// symlink or a `../` traversal with no canonicalization, so the automation
/// reaches files OUTSIDE the app's sandbox / container (iOS Shortcuts
/// CVE-2026-20677 symlink-race / CVE-2026-20653 path class).
///
/// This now runs on a real `dart:io` filesystem when available: [SandboxFs]
/// creates a real container dir, seeds an in-container note, seeds sensitive
/// files OUTSIDE the container, and PLANTS A real SYMLINK inside the container
/// that points outside it. The vulnerable [resolve] joins the Shortcuts path
/// against the container, follows the real symlink / `..` traversal WITHOUT
/// canonicalizing, and READS the file it lands on - so it reads the
/// out-of-sandbox secret off the real disk (adb-pullable). Under `flutter test`
/// (or when no platform dir / symlink support is available) it falls back to an
/// in-memory model so the demo stays offline and deterministic. The secure
/// [resolveSafe] canonicalizes (resolving symlinks) and asserts the real path
/// stays under the container root, rejecting escapes.
library;

import 'dart:io';

import '../../../core/evidence_sink.dart';

/// The outcome of resolving a Shortcuts-supplied path to a file read.
class FsResult {
  const FsResult({
    required this.read,
    required this.blocked,
    required this.realPath,
    this.contents,
    this.reason,
  });

  /// Whether a file was actually read.
  final bool read;

  /// Whether the safe resolver refused (secure path).
  final bool blocked;

  /// The canonical absolute path the request resolved to.
  final String realPath;

  /// The file body returned (null unless read).
  final String? contents;

  /// Why the safe resolver refused (secure path only).
  final String? reason;

  /// True when the resolved real path escaped the container root - the actual
  /// sandbox-escape hit.
  bool escapedSandbox(String containerRoot) =>
      read && !_within(realPath, containerRoot);

  static bool _within(String path, String root) =>
      path == root || path.startsWith('$root/');
}

class SandboxFs {
  SandboxFs();

  /// Lexical container root for evidence display / the in-memory fallback.
  static const String containerRoot = '/var/mobile/Containers/Data/App/DVMA';

  /// A Shortcuts payload that walks out of the container with `../`. On the
  /// in-memory fallback the container has 6 path segments plus `Documents`, so
  /// seven `../` pop back to `/` before descending to the out-of-sandbox
  /// secret. On the real device branch the same logical input is remapped to
  /// climb out of the real container (see [resolve]).
  static const String traversalInput =
      'Documents/../../../../../../../private/var/db/keychain.txt';

  /// A Shortcuts payload that lands on a symlink planted in the container which
  /// points OUTSIDE it (the CVE-2026-20677 symlink-race shape).
  static const String symlinkInput = 'Documents/backup_link/secrets.plist';

  /// A benign in-container request.
  static const String benignInput = 'Documents/notes.txt';

  /// The (virtual) file system used as the in-memory fallback under test.
  /// Includes in-container files AND sensitive files outside the container.
  final Map<String, String> _memFiles = const {
    '$containerRoot/Documents/notes.txt': 'grocery list',
    '/private/var/db/keychain.txt':
        'kc: device-passcode-hash 9f21ac...  (OUTSIDE SANDBOX)',
    '/private/var/mobile/Library/Secrets/secrets.plist':
        '<plist>apple-id-token: ey...SECRET</plist>  (OUTSIDE SANDBOX)',
  };

  /// In-memory symlink map (fallback under test): an in-container path -> the
  /// real directory it points to (OUTSIDE the container).
  final Map<String, String> _memSymlinks = const {
    '$containerRoot/Documents/backup_link':
        '/private/var/mobile/Library/Secrets',
  };

  // ---- Real filesystem state (populated by [_ensureSetup] on device). ----

  /// The real, on-device container root (null under test).
  String? _realContainer;

  static const String _keychainBody =
      'kc: device-passcode-hash 9f21ac...  (OUTSIDE SANDBOX)';
  static const String _plistBody =
      '<plist>apple-id-token: ey...SECRET</plist>  (OUTSIDE SANDBOX)';

  /// Resolves a real base dir. On Android this is the external files dir
  /// (adb-pullable); otherwise the app documents dir. Returns null under test.
  Future<String?> _resolveBaseDir() async {
    final base = await DvmaEvidence.writableBaseDir();
    return base == null ? null : '${base.path}/shortcuts_sandbox';
  }

  /// Builds the real on-device sandbox: a container dir with an in-bounds note,
  /// sensitive files OUTSIDE the container, and a real symlink inside the
  /// container pointing outside it. Best-effort: on failure we stay in the
  /// in-memory fallback. Returns the real container root, or null under test.
  Future<String?> _ensureSetup() async {
    if (_realContainer != null) return _realContainer;
    final base = await _resolveBaseDir();
    if (base == null) return null;
    try {
      final container = '$base/container';
      final outside = '$base/outside_secrets';
      // In-container note.
      final note = File('$container/Documents/notes.txt');
      await note.parent.create(recursive: true);
      await note.writeAsString('grocery list', flush: true);
      // Sensitive files that live OUTSIDE the container.
      final keychain = File('$outside/keychain.txt');
      await keychain.parent.create(recursive: true);
      await keychain.writeAsString(_keychainBody, flush: true);
      await File('$outside/secrets.plist')
          .writeAsString(_plistBody, flush: true);
      // Plant a real symlink inside the container that points outside it.
      final link = Link('$container/Documents/backup_link');
      if (await link.exists()) await link.delete();
      await link.create(outside, recursive: true);

      _realContainer = container;
      return container;
    } catch (_) {
      // Symlink / FS unsupported on this host: stay with the in-memory model.
      return null;
    }
  }

  /// Naive lexical join that collapses `.`/`..` with no confinement.
  static String _lexicalJoin(String base, String relative) {
    final segments = <String>[];
    final root = base.startsWith('/');
    for (final seg in '$base/$relative'.split('/')) {
      if (seg.isEmpty || seg == '.') continue;
      if (seg == '..') {
        if (segments.isNotEmpty) segments.removeLast();
      } else {
        segments.add(seg);
      }
    }
    return '${root ? '/' : ''}${segments.join('/')}';
  }

  /// Follows the in-memory symlink prefix WITHOUT re-confining (fallback only).
  String _followMemSymlinks(String path) {
    for (final entry in _memSymlinks.entries) {
      final key = _lexicalJoin('/', entry.key);
      if (path == key || path.startsWith('$key/')) {
        final rest = path.substring(key.length);
        return _lexicalJoin('/', '${entry.value}$rest');
      }
    }
    return path;
  }

  /// Maps a logical Shortcuts input (defined against the lexical container) to
  /// the equivalent path on the real container. The traversal input is rewritten
  /// to climb out of the real container (`$base/container` -> `$base`) into the
  /// seeded `outside_secrets` dir; the symlink + benign inputs are unchanged
  /// (the planted symlink itself does the escaping on disk).
  String _realShortcutPath(String shortcutPath) {
    if (shortcutPath == traversalInput) {
      // From $base/container/Documents, `..` x2 reaches $base.
      return 'Documents/../../outside_secrets/keychain.txt';
    }
    return shortcutPath;
  }

  /// VULN: resolve the Shortcuts path against the container, collapse `..`, and
  /// follow symlinks - but never verify the real path stays inside the
  /// container - then READ the file. Traversal and planted symlinks escape the
  /// sandbox on the real filesystem. Falls back to the in-memory model.
  Future<FsResult> resolve(String shortcutPath) async {
    final container = await _ensureSetup();
    if (container != null) {
      // Join against the real container with no confinement...
      final joined = _lexicalJoin(container, _realShortcutPath(shortcutPath));
      String real = joined;
      String? body;
      try {
        // ...and let dart:io resolve any real symlinks in the path, then read.
        final file = File(joined);
        if (await file.exists()) {
          real = await file.resolveSymbolicLinks();
          body = await file.readAsString();
        } else {
          real = _lexicalJoin('/', joined);
        }
      } catch (_) {
        body = null;
      }
      if (body != null) {
        DvmaEvidence.record(
          'shortcuts_path_symlink_sandbox_escape',
          'sandbox-escape',
          'wrote: $real\n$body',
        );
      }
      return FsResult(
        read: true,
        blocked: false,
        realPath: real,
        contents: body ?? '(no file at $real)',
        reason: 'resolved with no canonicalization / confinement',
      );
    }

    // In-memory fallback (under test).
    final joined = _lexicalJoin(containerRoot, shortcutPath);
    final real = _followMemSymlinks(joined);
    final memBody = _memFiles[_lexicalJoin('/', real)] ?? _memFiles[real];
    if (memBody != null) {
      DvmaEvidence.record(
        'shortcuts_path_symlink_sandbox_escape',
        'sandbox-escape',
        'wrote: $real\n$memBody',
      );
    }
    return FsResult(
      read: true,
      blocked: false,
      realPath: real,
      contents: memBody ?? '(no file at $real)',
      reason: 'resolved with no canonicalization / confinement',
    );
  }

  /// SECURE contrast: resolve exactly as above (canonicalize + follow symlinks),
  /// then assert the real path is still under the container root before any
  /// read. Escapes are rejected.
  Future<FsResult> resolveSafe(String shortcutPath) async {
    final container = await _ensureSetup();
    if (container != null) {
      final joined = _lexicalJoin(container, _realShortcutPath(shortcutPath));
      String real = _lexicalJoin('/', joined);
      try {
        final file = File(joined);
        if (await file.exists()) real = await file.resolveSymbolicLinks();
      } catch (_) {
        // Use the lexical resolution for the confinement check.
      }
      final within = real == container || real.startsWith('$container/');
      if (!within) {
        return FsResult(
          read: false,
          blocked: true,
          realPath: real,
          reason: 'real path escapes container root $container',
        );
      }
      String? body;
      try {
        body = await File(joined).readAsString();
      } catch (_) {
        body = null;
      }
      return FsResult(
        read: true,
        blocked: false,
        realPath: real,
        contents: body ?? '(no file at $real)',
        reason: 'canonical path confined to container',
      );
    }

    // In-memory fallback (under test).
    final joined = _lexicalJoin(containerRoot, shortcutPath);
    final real = _followMemSymlinks(joined);
    final within = real == containerRoot || real.startsWith('$containerRoot/');
    if (!within) {
      return FsResult(
        read: false,
        blocked: true,
        realPath: real,
        reason: 'real path escapes container root $containerRoot',
      );
    }
    final body = _memFiles[real];
    return FsResult(
      read: true,
      blocked: false,
      realPath: real,
      contents: body ?? '(no file at $real)',
      reason: 'canonical path confined to container',
    );
  }

  /// The container root actually in use (real path on device, else lexical).
  Future<String> activeContainerRoot() async =>
      (await _ensureSetup()) ?? containerRoot;
}
