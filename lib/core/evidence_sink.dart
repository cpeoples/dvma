import 'dart:async';
import 'dart:developer' as developer;
import 'dart:io';

import 'package:path_provider/path_provider.dart';

/// Capture surface for the DVMA dynamic-analysis harness.
///
/// When a module performs a *real* insecure action (writes cleartext to disk,
/// sends a request over the wire, produces recoverable ciphertext, leaks a
/// token to the log), it also calls [DvmaEvidence.record] so the artifact is
/// mirrored to an adb-pullable location and emitted to logcat under a stable
/// tag. This is what `automation/scripts/capture_run.sh` collects to build the
/// per-module "what was actually exfiltrated" report.
///
/// This is not a security control, it is deliberately an exfiltration channel
/// so a trainee/harness can observe the leak with `adb` and `logcat`. The real
/// vulnerable I/O (the SharedPreferences XML, the SQLite db, the socket write)
/// still happens independently; the sink just makes it easy to find.
class DvmaEvidence {
  DvmaEvidence._();

  /// logcat tag the harness greps for (`adb logcat -s DVMA-EVIDENCE:*`).
  static const String logTag = 'DVMA-EVIDENCE';

  /// Subdirectory (under the app's external files dir) the harness pulls.
  static const String artifactDir = 'dvma-artifacts';

  /// Records a real artifact for [vulnId]:
  ///  * appends a line to logcat under [logTag] (always), and
  ///  * appends `<vulnId>.txt` in the pullable artifact dir (best effort).
  ///
  /// [kind] is a short label for the artifact (`prefs`, `ciphertext`,
  /// `http-request`, `file`, `token`, ...). Never throws, evidence capture
  /// must not perturb the vulnerable path being demonstrated.
  static Future<void> record(
    String vulnId,
    String kind,
    String artifact,
  ) async {
    final line = '[$vulnId] $kind :: ${_singleLine(artifact)}';
    developer.log(line, name: logTag);

    try {
      final file = await _artifactFile(vulnId);
      if (file == null) return;
      final stamp = DateTime.now().toIso8601String();
      await file.writeAsString(
        '$stamp\t$kind\n$artifact\n\n',
        mode: FileMode.append,
        flush: true,
      );
    } catch (_) {
      // Best effort: on hosts without an external files dir (or in unit tests)
      // the logcat line above is still emitted.
    }
  }

  /// Absolute path to the pullable artifact directory, or null if unavailable
  /// (e.g. iOS/desktop/test host). Exposed so a module can also drop a real
  /// file (temp/backup/sdcard demos) into the same collected location.
  static Future<String?> artifactDirPath() async {
    final dir = await _externalDir();
    return dir?.path;
  }

  /// A writable base directory a module can drop a real artifact file into, or
  /// null on a host without one (desktop / unit tests). On Android this prefers
  /// the adb-pullable external files dir and falls back to the app documents
  /// dir; elsewhere it is the documents dir. Never throws, modules that write
  /// their own files (SBOM, backups, leaked dumps) share this resolution rather
  /// than each re-deriving the platform branch.
  static Future<Directory?> writableBaseDir() async {
    if (Platform.isAndroid) {
      try {
        final ext = await getExternalStorageDirectory();
        if (ext != null) return ext;
      } catch (_) {
        // External storage unavailable (e.g. under `flutter test`); fall
        // through to the documents dir below.
      }
    }
    try {
      return await getApplicationDocumentsDirectory();
    } catch (_) {
      return null;
    }
  }

  static Future<File?> _artifactFile(String vulnId) async {
    final dir = await _externalDir();
    if (dir == null) return null;
    return File('${dir.path}/$vulnId.txt');
  }

  static Directory? _cachedDir;

  static Future<Directory?> _externalDir() async {
    if (_cachedDir != null) return _cachedDir;
    if (!Platform.isAndroid && !Platform.isIOS) return null;
    try {
      // On Android this is /storage/emulated/0/Android/data/<pkg>/files, which
      // `adb pull` can read without root. On iOS it is the app documents dir.
      final base = Platform.isAndroid
          ? await getExternalStorageDirectory()
          : await getApplicationDocumentsDirectory();
      if (base == null) return null;
      final dir = Directory('${base.path}/$artifactDir');
      await dir.create(recursive: true);
      _cachedDir = dir;
      return dir;
    } catch (_) {
      return null;
    }
  }

  static String _singleLine(String s) {
    final flat = s.replaceAll('\n', ' \u23ce ').trim();
    return flat.length <= 300 ? flat : '${flat.substring(0, 297)}...';
  }
}
