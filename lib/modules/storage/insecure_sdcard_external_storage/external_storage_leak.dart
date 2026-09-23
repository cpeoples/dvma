import 'dart:io';

import '../../../core/evidence_sink.dart';

/// Insecure SD-card / external storage helper.
///
/// INTENTIONALLY VULNERABLE (CWE-312 / CWE-921): writes a sensitive file to a
/// shared / external ("world-readable") storage location. On Android, external
/// storage (`getExternalStorageDirectory`) is readable by any app holding a
/// storage permission and by anyone with `adb`/a file-manager app. The file
/// below contains cleartext secrets, so it leaks the moment it is written.
///
/// The write happens on-device: on Android it lands in the app's external
/// files dir (adb-pullable without root); on non-Android platforms it falls
/// back to the app documents dir so the demo still produces a real file. The
/// logic is factored out of the widget so a regression test can assert the
/// file is written to a shared location and its contents are readable back in
/// cleartext. Under `flutter test` (or when the platform returns null) we fall
/// back to an in-memory file system so the demo stays offline and deterministic.
class ExternalStorageLeak {
  ExternalStorageLeak._();

  static const String fileName = 'dvma_secrets.txt';

  /// In-memory fallback used under test / when no external dir is available.
  static final Map<String, String> _memoryFs = {};

  /// Resolves the (world-readable) external/shared storage directory. On
  /// Android this is the external files dir; on other platforms it falls back
  /// to the app documents dir, then to an in-memory path for tests.
  static Future<String> _sharedDir() async {
    final base = await DvmaEvidence.writableBaseDir();
    // No external/docs dir (e.g. under `flutter test`): use an in-memory path.
    return base?.path ?? '/sdcard/Android/data/dvma/files';
  }

  /// VULN: writes [secret] to a world-readable file with no encryption.
  ///
  /// Returns the full path the file was written to.
  static Future<String> writeSensitiveFile(String secret) async {
    final dir = await _sharedDir();
    final path = '$dir/$fileName';
    try {
      final file = File(path);
      await file.parent.create(recursive: true);
      await file.writeAsString(secret, flush: true);
    } catch (_) {
      // In-memory fallback so the demo is deterministic offline / under test.
      _memoryFs[path] = secret;
    }
    return path;
  }

  /// Simulates another app / adb reading the file back. Returns the cleartext
  /// contents, proving the data is world-readable.
  static Future<String> readAsOtherApp(String path) async {
    try {
      final file = File(path);
      if (await file.exists()) return await file.readAsString();
    } catch (_) {
      // Fall through to the in-memory fallback.
    }
    return _memoryFs[path] ?? '';
  }

  /// Test/demo helper to reset the in-memory fallback fs.
  static void resetMemoryFs() => _memoryFs.clear();
}
