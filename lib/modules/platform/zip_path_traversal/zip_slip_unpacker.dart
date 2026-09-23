import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:archive/archive.dart';

import '../../../core/evidence_sink.dart';

/// Zip-slip (path-traversal) helper.
///
/// INTENTIONALLY VULNERABLE (CWE-22): an "update package" unpacker that joins
/// each archive entry name to the target dir WITHOUT checking that the result
/// stays inside that dir, then WRITES the entry there. A crafted entry like
/// `../../../../tmp/x` escapes the destination and overwrites arbitrary files.
///
/// The extraction happens on a real `dart:io` filesystem: the traversing entry
/// is written OUTSIDE the intended extract dir, producing an adb-pullable file
/// that proves the escape. Under `flutter test` (or when the platform channel
/// is unavailable) it falls back to an in-memory map so the demo stays offline
/// and deterministic. [resolveTargetPath] stays pure so a unit test can assert
/// the malicious entry still resolves outside the base dir.
class ZipSlipUnpacker {
  ZipSlipUnpacker._();

  /// The malicious entry name a real attacker would ship.
  static const String maliciousEntry = '../../../../tmp/dvma_pwned.txt';

  /// In-memory fallback used under test / when no writable dir is available.
  static final Map<String, String> _memoryFs = {};

  /// Builds an in-memory zip containing one benign and one traversal entry.
  static Uint8List craftMaliciousZip() {
    final good = utf8.encode('{}\n');
    final bad = utf8.encode('pwn\n');
    final archive = Archive()
      ..addFile(ArchiveFile('update/config.json', good.length, good))
      ..addFile(ArchiveFile(maliciousEntry, bad.length, bad));
    return Uint8List.fromList(ZipEncoder().encode(archive));
  }

  /// Collapses `.`/`..` segments the way a filesystem would, with no check that
  /// the result stays under [baseDir] (that missing check is the bug).
  static String resolveTargetPath(String baseDir, String entryName) {
    final segments = <String>[];
    for (final part in '$baseDir/$entryName'.split('/')) {
      if (part.isEmpty || part == '.') continue;
      if (part == '..') {
        if (segments.isNotEmpty) segments.removeLast();
      } else {
        segments.add(part);
      }
    }
    return '/${segments.join('/')}';
  }

  /// Whether [resolved] escaped [baseDir]. A safe unpacker would refuse when
  /// this is true; the vulnerable one writes anyway.
  static bool escapesBase(String baseDir, String resolved) {
    final normalizedBase = resolveTargetPath(baseDir, '');
    return !resolved.startsWith('$normalizedBase/') &&
        resolved != normalizedBase;
  }

  /// Resolves a real, writable extract dir. On Android this is the external
  /// files dir (adb-pullable); otherwise the app documents dir. Returns null
  /// under test / when no platform dir is available.
  static Future<String?> _realExtractDir() async {
    final base = await DvmaEvidence.writableBaseDir();
    return base == null ? null : '${base.path}/update';
  }

  /// VULN: extract every entry of [zipBytes] by joining its name to the extract
  /// dir with no containment check and WRITING it to disk. The `../` entry
  /// therefore escapes the extract dir onto the real filesystem. Returns the
  /// absolute path each entry was written to (exactly where the vulnerable code
  /// wrote it). Falls back to an in-memory map under test.
  static Future<List<String>> unpackToDisk(Uint8List zipBytes) async {
    final archive = ZipDecoder().decodeBytes(zipBytes);
    final realBase = await _realExtractDir();
    // The lexical base used for evidence/verdict rendering.
    final displayBase = realBase ?? '/data/data/com.dvma/files/update';
    final written = <String>[];

    for (final f in archive.files) {
      // VULN: no check that the join stays under the extract dir.
      final resolved = realBase == null
          ? resolveTargetPath(displayBase, f.name)
          : resolveTargetPath(realBase, f.name);
      final bytes = f.content as List<int>;
      var wroteToDisk = false;
      if (realBase != null) {
        try {
          final file = File(resolved);
          await file.parent.create(recursive: true);
          await file.writeAsBytes(bytes, flush: true);
          wroteToDisk = true;
        } catch (_) {
          // Fall through to in-memory fallback for this entry.
        }
      }
      if (!wroteToDisk) {
        _memoryFs[resolved] = utf8.decode(bytes, allowMalformed: true);
      }
      written.add(resolved);

      // Mirror the escaping entry to the evidence sink (fire-and-forget).
      if (escapesBase(displayBase, resolveTargetPath(displayBase, f.name)) ||
          (realBase != null && escapesBase(realBase, resolved))) {
        final body = utf8.decode(bytes, allowMalformed: true);
        DvmaEvidence.record(
          'zip_path_traversal',
          'zip-slip',
          'wrote: $resolved\n$body',
        );
      }
    }
    return written;
  }

  /// The lexical extract base used for display/verdict when a real dir is not
  /// yet known (kept for the pure containment check in the UI/tests).
  static const String lexicalBaseDir = '/data/data/com.dvma/files/update';

  /// Simulates unpacking without writing: returns the resolved target path for
  /// every entry (pure; retained for tests and secure-contrast display).
  static List<String> unpackTargets(Uint8List zipBytes, String baseDir) {
    final archive = ZipDecoder().decodeBytes(zipBytes);
    return archive.files
        .map((f) => resolveTargetPath(baseDir, f.name))
        .toList();
  }

  /// Test/demo helper to reset the in-memory fallback fs.
  static void resetMemoryFs() => _memoryFs.clear();
}
