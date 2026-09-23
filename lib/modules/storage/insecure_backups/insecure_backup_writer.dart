import 'dart:convert';
import 'dart:io';

import 'package:path_provider/path_provider.dart';

/// Insecure backups helper.
///
/// INTENTIONALLY VULNERABLE (CWE-530 / CWE-312): android:allowBackup=true with
/// no backup rules (and no iOS NSURLIsExcludedFromBackupKey) means the full app
/// sandbox, including this backup blob of tokens/PII, is swept into an
/// unauthenticated `adb backup` / iTunes/iCloud backup.
///
/// This writes a JSON file into the app documents dir (which lives under
/// the app sandbox that backups capture). Under `flutter test` (or when the
/// platform channel is unavailable) it falls back to [Directory.systemTemp] so
/// the demo still produces a real file.
class InsecureBackupWriter {
  InsecureBackupWriter._();

  static const String fileName = 'dvma_backup_blob.json';

  static Future<Directory> _docsDir() async {
    try {
      return await getApplicationDocumentsDirectory();
    } catch (_) {
      return Directory.systemTemp;
    }
  }

  /// VULN: writes a cleartext JSON blob of tokens/PII into the backed-up app
  /// sandbox. Returns the [File] so the caller can surface its path/contents.
  static Future<File> writeBackupBlob() async {
    final dir = await _docsDir();
    final blob = const JsonEncoder.withIndent('  ').convert({
      'session': 'active',
      'auth_token': 'DVMA{backup_leak}.eyJhbGciOiJIUzI1NiJ9.session',
      'refresh_token': 'rt_9a1f77c2d4e8b3c19f',
      'pin': '1337',
      'user': {
        'email': 'victim@example.com',
        'ssn': '123-45-6789',
        'card': '4111 1111 1111 1111',
      },
    });
    final file = File('${dir.path}/$fileName');
    await file.writeAsString(blob, flush: true);
    return file;
  }
}
