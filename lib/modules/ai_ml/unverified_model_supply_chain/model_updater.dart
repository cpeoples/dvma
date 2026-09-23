import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;

import '../../../core/config/dvma_env.dart';

/// Unverified model supply-chain helper.
///
/// INTENTIONALLY VULNERABLE (CWE-494 / CWE-345): model updates are fetched from
/// an unauthenticated (plain-HTTP) URL with no checksum/signature verification,
/// so an on-path attacker or malicious mirror serves a poisoned model and it is
/// accepted. A safe updater pins HTTPS + verifies a signature/known hash.
///
/// Pure Dart so a unit test can assert a tampered model is still accepted.
class ModelUpdater {
  ModelUpdater();

  /// Unauthenticated source (note: http, not https). The real fetch below
  /// targets [DvmaEnv.network.insecureUpdateUrl] (the local cleartext capture
  /// listener); this constant is the documentation-facing example mirror.
  static const String updateUrl = 'http://models.dvma.example/latest.tflite';

  /// The plaintext URL the real over-the-wire fetch hits (the trainee's own
  /// cleartext capture listener by default).
  static String get liveUpdateUrl => DvmaEnv.network.insecureUpdateUrl;

  /// Whether a checksum/signature is verified before accepting (it is not).
  static const bool verifiesChecksum = false;

  final List<String> accepted = [];

  /// Computes the hash for display only, it is never compared to a trusted
  /// pinned value.
  static String sha256Of(String bytes) =>
      sha256.convert(utf8.encode(bytes)).toString();

  /// "Downloads" and accepts the model with no verification.
  String fetchAndInstall(String downloadedBytes) {
    accepted.add(downloadedBytes);
    return 'installed model from $updateUrl\n'
        'sha256=${sha256Of(downloadedBytes)} (never checked)\n'
        'verifiesChecksum = $verifiesChecksum';
  }

  /// VULN: performs the real over-the-wire fetch. A plaintext `http.get` hits
  /// [liveUpdateUrl] and whatever the (attacker-controllable) mirror returns is
  /// installed verbatim, no checksum, no signature, no HTTPS. Returns the raw
  /// bytes that were accepted so the caller can record the real artifact.
  ///
  /// Degrades gracefully offline: if the fetch throws or returns an empty body
  /// it falls back to [fallbackBytes] (the deterministic poisoned stand-in) so
  /// the demo still installs an unverified artifact without a listener running.
  Future<ModelFetchResult> fetchAndInstallOverHttp(String fallbackBytes) async {
    final uri = Uri.parse(liveUpdateUrl);
    var bytes = fallbackBytes;
    var overTheWire = false;
    try {
      final resp = await http.get(uri).timeout(const Duration(seconds: 6));
      if (resp.bodyBytes.isNotEmpty) {
        // Accept whatever the mirror served, decoded as text for display.
        bytes = utf8.decode(resp.bodyBytes, allowMalformed: true);
        overTheWire = true;
      }
    } catch (_) {
      // No listener / offline: keep the poisoned fallback so the unverified
      // install still happens (and is recorded) without network.
    }
    accepted.add(bytes); // installed with no verification
    return ModelFetchResult(
      url: liveUpdateUrl,
      bytes: bytes,
      overTheWire: overTheWire,
      sha256: sha256Of(bytes),
    );
  }
}

/// The result of a real (or fallback) unverified model fetch+install.
class ModelFetchResult {
  ModelFetchResult({
    required this.url,
    required this.bytes,
    required this.overTheWire,
    required this.sha256,
  });

  /// The plaintext URL the fetch targeted.
  final String url;

  /// The bytes that were installed (never checksum-verified).
  final String bytes;

  /// True when bytes actually arrived over the wire (listener responded).
  final bool overTheWire;

  /// The hash of [bytes], computed for display only, never compared.
  final String sha256;
}
