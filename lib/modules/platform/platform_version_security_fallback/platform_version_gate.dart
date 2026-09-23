/// Platform-Version Security Fallback helper.
///
/// INTENTIONALLY VULNERABLE (CWE-636 / CWE-1188 / CWE-693): a security decision
/// is gated on the OS version (`if (SDK_INT >= X)` / `@available`) and SILENTLY
/// falls back to an insecure path on older versions. Here the sensitive op is
/// storing a key with hardware backing (StrongBox / Secure Enclave), which
/// requires OS version >= a threshold. On an older OS the "fail-open" code
/// stores the key in software/plaintext and proceeds as if nothing happened, so
/// devices below the threshold run without the protection the code appears to
/// provide. The failure mode is failing OPEN instead of failing CLOSED
/// (Android/iOS version-fallback class, MASTG-TEST-0245).
///
/// This is an offline + deterministic SIMULATION. [PlatformVersionGate] models
/// an `osVersion` and a hardware-backing threshold. The vulnerable [storeKey]
/// silently downgrades to software storage on old OSes; the secure
/// [storeKeySafe] fails closed (refuses the sensitive op) when the platform
/// cannot provide the hardware guarantee, and stores hardware-backed on a
/// supported OS.
library;

/// The outcome of attempting to store a key under a platform-version gate.
class KeyStorageResult {
  const KeyStorageResult({
    required this.osVersion,
    required this.stored,
    required this.hardwareBacked,
    required this.proceededInsecurely,
    this.denyReason,
  });

  /// The OS/SDK version the operation ran under.
  final int osVersion;

  /// Whether the key was persisted.
  final bool stored;

  /// Whether the key is backed by hardware (StrongBox / Secure Enclave).
  final bool hardwareBacked;

  /// Whether an old OS silently proceeded with software/plaintext storage
  /// instead of the advertised hardware backing - the hit.
  final bool proceededInsecurely;

  /// Why the secure path refused (fails-closed) on an unsupported OS.
  final String? denyReason;
}

class PlatformVersionGate {
  const PlatformVersionGate();

  /// Minimum OS/SDK version that supports hardware-backed keys (e.g. Android
  /// API 28 introduced StrongBox).
  static const int hardwareBackingThreshold = 28;

  /// An OS below the threshold (no hardware-backed key support).
  static const int oldOsVersion = 25;

  /// An OS at/above the threshold (hardware-backed keys available).
  static const int newOsVersion = 33;

  /// VULN: gate hardware backing on the OS version, but SILENTLY fall back to
  /// software/plaintext storage on older versions and proceed - so the caller
  /// believes the key is protected when it is not.
  KeyStorageResult storeKey(int osVersion) {
    if (osVersion >= hardwareBackingThreshold) {
      return KeyStorageResult(
        osVersion: osVersion,
        stored: true,
        hardwareBacked: true,
        proceededInsecurely: false,
      );
    }
    // Silent downgrade: store in software and proceed as if secure.
    return KeyStorageResult(
      osVersion: osVersion,
      stored: true,
      hardwareBacked: false,
      proceededInsecurely: true,
      denyReason:
          'silent fallback: no StrongBox on API < '
          '$hardwareBackingThreshold; stored in software/plaintext',
    );
  }

  /// SECURE contrast: fail CLOSED. If the platform cannot provide the hardware
  /// guarantee, refuse the sensitive op rather than silently downgrading. On a
  /// supported OS, store the key hardware-backed.
  KeyStorageResult storeKeySafe(int osVersion) {
    if (osVersion < hardwareBackingThreshold) {
      return KeyStorageResult(
        osVersion: osVersion,
        stored: false,
        hardwareBacked: false,
        proceededInsecurely: false,
        denyReason:
            'unsupported OS (API $osVersion < '
            '$hardwareBackingThreshold): hardware-backed key unavailable; '
            'fails closed - sensitive op refused',
      );
    }
    return KeyStorageResult(
      osVersion: osVersion,
      stored: true,
      hardwareBacked: true,
      proceededInsecurely: false,
    );
  }
}
