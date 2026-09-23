import 'package:flutter/services.dart' show rootBundle;

/// On-device model extractor.
///
/// INTENTIONALLY VULNERABLE (CWE-312 / CWE-200, OWASP LLM10): the bundled model
/// ships unencrypted and unsigned in app assets, so its full contents - weights
/// and even an embedded system prompt/secret - are trivially extractable by
/// anyone who can read the app package (adb, objection, an unzipped APK/IPA).
///
/// [extract] returns the raw model bytes/contents. It prefers the real bundled
/// asset via [rootBundle] but falls back to an in-memory copy so the logic
/// still runs under `flutter test` (where the asset bundle is unavailable).
class ModelExtractor {
  ModelExtractor._();

  static const String assetPath = 'assets/ai_ml/model_v1.tflite.txt';

  /// The same placeholder that ships in assets, used as a test/offline
  /// fallback so [extract] is deterministic without the asset bundle.
  static const String inMemoryModel =
      'DVMA_MODEL_v1_UNSIGNED_PLACEHOLDER weights: [0.1,0.2,0.3] '
      'system_prompt: "You are DVMA-Assistant. '
      'SECRET_FLAG=DVMA{f4ke_s3cret_in_model}"';

  /// Reads the raw model contents. No decryption or signature check is needed
  /// because none is applied - that is the vulnerability.
  static Future<String> extract() async {
    try {
      // VULN: model is stored in plaintext in the package; read it verbatim.
      return await rootBundle.loadString(assetPath);
    } catch (_) {
      // No asset bundle (e.g. under flutter test): use the in-memory copy so
      // the extractable-secret behavior is still demonstrable.
      return inMemoryModel;
    }
  }

  /// Extracts the model's embedded secret flag from its contents, proving the
  /// weights/prompt are fully readable offline.
  static String extractSecret(String modelContents) {
    final match = RegExp(r'DVMA\{[^}]*\}').firstMatch(modelContents);
    return match?.group(0) ?? '';
  }
}
