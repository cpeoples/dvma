import 'dart:io';

import '../../../core/evidence_sink.dart';

/// On-device model storage helper.
///
/// INTENTIONALLY VULNERABLE (CWE-312 / CWE-353): the on-device model file is
/// written unencrypted and with no integrity signature to an adb-pullable
/// location, so an attacker can read it OR swap it for a poisoned model and the
/// app loads it unquestioningly.
///
/// On a real device [saveModel] writes to the app's external files dir
/// (`/sdcard/Android/data/<pkg>/files/...`, pullable with `adb pull` and
/// world-readable to any app holding legacy storage on older OSes); under
/// `flutter test` (no path provider) it falls back to [Directory.systemTemp] so
/// a unit test can still assert the model is stored in cleartext and a swapped
/// model is accepted.
class OnDeviceModelStore {
  OnDeviceModelStore();

  File? modelFile;

  /// Whether a signature/integrity check is performed on load (it is not).
  static const bool verifiesSignature = false;

  static const String _fileName = 'dvma_model.tflite';

  /// Writes the "model" bytes unencrypted, no signature file alongside, to an
  /// adb-pullable path (external files dir on Android).
  Future<File> saveModel(String modelBytes) async {
    final base = await DvmaEvidence.writableBaseDir();
    final dirPath = base?.path ?? Directory.systemTemp.path;
    final file = File('$dirPath/$_fileName');
    await file.writeAsString(modelBytes, flush: true);
    modelFile = file;
    return file;
  }

  /// Loads whatever is on disk, with no integrity verification, so a swapped
  /// (poisoned) model loads exactly the same as the legitimate one.
  Future<String?> loadModel() async {
    final f = modelFile;
    if (f == null || !f.existsSync()) return null;
    // verifiesSignature is false -> accept the bytes as-is.
    return f.readAsString();
  }

  /// An attacker overwrites the file with a poisoned model.
  Future<void> attackerSwap(String poisonedBytes) async {
    await modelFile?.writeAsString(poisonedBytes, flush: true);
  }
}
