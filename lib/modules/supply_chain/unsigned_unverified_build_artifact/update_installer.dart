import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import '../../../core/evidence_sink.dart';

/// Unsigned/unverified update helper.
///
/// INTENTIONALLY VULNERABLE (CWE-347 / CWE-494): fetches and applies an update
/// artifact with no signature check and no checksum verification, so an on-path
/// attacker (or malicious mirror) swaps in a trojaned artifact and it installs.
///
/// Pure Dart so a unit test can assert a tampered artifact is still "applied".
class UpdateInstaller {
  UpdateInstaller();

  final List<String> installed = [];

  /// Computes the artifact's actual hash (for display only, it is never
  /// compared against a trusted value).
  static String sha256Of(String artifactBytes) =>
      sha256.convert(utf8.encode(artifactBytes)).toString();

  /// "Applies" the update. Note there is no `expectedHash`/signature parameter
  /// at all: whatever bytes arrive are installed.
  String apply(String artifactBytes) {
    installed.add(artifactBytes);
    return 'installed ${artifactBytes.length} bytes '
        '(sha256=${sha256Of(artifactBytes)}) with NO verification';
  }

  /// The on-disk name the unsigned/unverified artifact is written to.
  static const String artifactFileName = 'installed_update.apk';

  /// VULN (real I/O): "installs" the update by writing the fetched, UNSIGNED,
  /// unverified artifact bytes to a real file on disk, the signature/checksum
  /// is never checked before it lands. Returns the absolute path written (or a
  /// fallback marker on hosts without a writable dir). Never throws.
  Future<String> applyToDisk(String artifactBytes) async {
    installed.add(artifactBytes);
    final baseDir = await DvmaEvidence.writableBaseDir();
    if (baseDir == null) return '(no writable dir on this host)';
    try {
      final file = File('${baseDir.path}/$artifactFileName');
      await file.parent.create(recursive: true);
      // No signature/checksum verification, whatever bytes arrived are written.
      await file.writeAsBytes(utf8.encode(artifactBytes), flush: true);
      return file.path;
    } catch (_) {
      return '(write failed on this host)';
    }
  }
}
