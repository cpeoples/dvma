import 'dart:io';

import 'package:path_provider/path_provider.dart';

/// Temp/cache leftover helper.
///
/// INTENTIONALLY VULNERABLE (CWE-459 / CWE-312): writes decrypted, sensitive
/// content into a world-accessible temp/cache directory and never deletes it.
/// A secure app would keep plaintext in memory, use a protected directory, and
/// securely wipe temp files immediately after use.
///
/// On a real device this uses [getTemporaryDirectory] (the app cache dir, e.g.
/// `/data/data/<pkg>/cache` on Android), which is recoverable via adb / a file
/// browser / forensic tooling and is swept into `adb backup`. Under
/// `flutter test` (or when the platform channel is unavailable) it falls back
/// to [Directory.systemTemp] so a unit test can still assert the leftover.
class TempFileLeaker {
  TempFileLeaker();

  /// Predictable, non-unique leftover filename (cleartext contents, no cleanup).
  static const String fileName = 'dvma_decrypted_export.txt';

  File? lastFile;

  /// Resolves the (real, on-device) temp/cache directory the export leaks into.
  Future<Directory> _tempDir() async {
    try {
      return await getTemporaryDirectory();
    } catch (_) {
      // Platform channel unavailable (e.g. under `flutter test`).
      return Directory.systemTemp;
    }
  }

  /// Writes [sensitive] to a predictable temp file and leaves it there.
  Future<File> writeDecryptedToTemp(String sensitive) async {
    final dir = await _tempDir();
    // Predictable, non-unique name; cleartext contents; no cleanup.
    final file = File('${dir.path}/$fileName');
    await file.writeAsString(sensitive, flush: true);
    lastFile = file;
    return file;
  }

  /// Reads back the leftover (as a forensic tool / another app would).
  Future<String?> readLeftover() async {
    final f = lastFile;
    if (f == null || !f.existsSync()) return null;
    return f.readAsString();
  }
}
