/// Unsafe Media / Image Decoding helper.
///
/// INTENTIONALLY VULNERABLE (CWE-20 / CWE-1284): untrusted image/media headers
/// are trusted verbatim and passed to a decoder with no type, size, or
/// dimension validation. A decompression bomb declaring e.g. 100000x100000
/// pixels causes an absurd `width * height * 4` allocation (OOM), and spoofed
/// / unknown formats are accepted - the Samsung CVE-2025-21043 class.
///
/// [decode] is a PURE MATH model of the missing app-side validation kept for
/// the unit tests. [decodeReal] goes further: it actually attempts to allocate
/// the attacker-declared pixel buffer as a `Uint8List` inside a try/catch so
/// the real over-allocation is observed (an `OutOfMemoryError` / range error is
/// caught and reported instead of a hypothetical number). [decodeSafe]
/// enforces a format allowlist and max dimension/byte caps and rejects the bomb
/// BEFORE any allocation is attempted.
library;

import 'dart:typed_data';

class MediaDecoder {
  MediaDecoder._();

  /// Bytes-per-pixel assumed by the (naive) decoder for an RGBA bitmap.
  static const int bytesPerPixel = 4;

  /// Secure caps: reject anything larger than these.
  static const int maxDimension = 8192; // 8192 x 8192 max
  static const int maxByteLength = 64 * 1024 * 1024; // 64 MiB declared bytes

  /// Formats a hardened decoder will accept.
  static const Set<String> allowedFormats = {'png', 'jpeg', 'webp', 'gif'};

  /// VULN: trust the declared header and compute the allocation with no cap.
  /// Returns the (possibly absurd) allocation the decoder would attempt. It
  /// also accepts unknown/spoofed formats.
  static DecodeResult decode(MediaHeader header) {
    // No format check, no dimension cap, no byte-length sanity check.
    final allocationBytes = header.width * header.height * bytesPerPixel;
    final wouldOom = allocationBytes > maxByteLength;
    return DecodeResult(
      accepted: true,
      allocationBytes: allocationBytes,
      wouldOom: wouldOom,
      reason:
          'decoded ${header.format} at ${header.width}x${header.height} '
          '(allocated ${_humanBytes(allocationBytes)}, no validation)',
    );
  }

  /// Demo ceiling for the real allocation attempt. Requesting a buffer at or
  /// beyond this reliably throws (OutOfMemoryError / RangeError) on a phone or
  /// CI host, so the over-allocation is *observed* rather than modeled, but we
  /// never busy-fill tens of GB and hard-crash the process. The vulnerable path
  /// still trusts the attacker dimensions; this cap only bounds how much we try
  /// to grab before the runtime refuses.
  static const int _realAllocCeiling = 2 * 1024 * 1024 * 1024; // 2 GiB

  /// VULN (real): trust the declared header and actually attempt to allocate
  /// the pixel buffer as a `Uint8List`. No format/dimension/byte check. The
  /// attempted byte count is `width * height * 4` (clamped to [_realAllocCeiling]
  /// so a 10-billion-pixel bomb throws rather than wedging the host). Any
  /// `OutOfMemoryError` / `RangeError` from the runtime is CAUGHT and reported -
  /// that thrown allocation IS the observable effect. Returns the declared
  /// dimensions, the attempted byte count, and the real outcome.
  static RealDecodeResult decodeReal(MediaHeader header) {
    // VULN: attacker-declared dimensions drive the allocation with no cap.
    final declaredBytes = header.width * header.height * bytesPerPixel;
    final attemptBytes = declaredBytes > _realAllocCeiling
        ? _realAllocCeiling
        : declaredBytes;

    Uint8List? buffer;
    var allocated = false;
    String outcome;
    try {
      // real over-allocation: this genuinely asks the runtime for the buffer.
      buffer = Uint8List(attemptBytes);
      // Touch one byte so the allocation is not optimized away.
      if (buffer.isNotEmpty) buffer[0] = 1;
      allocated = true;
      outcome =
          'allocation SUCCEEDED (${_humanBytes(attemptBytes)} committed) '
          '- on a memory-constrained device the full '
          '${_humanBytes(declaredBytes)} would OOM the process';
    } on Object catch (e) {
      // OutOfMemoryError / RangeError etc., the real DoS made observable.
      outcome =
          'allocation FAILED: ${e.runtimeType} '
          '(attempted ${_humanBytes(attemptBytes)} of a declared '
          '${_humanBytes(declaredBytes)})';
    } finally {
      buffer = null; // let it be collected
    }

    return RealDecodeResult(
      declaredWidth: header.width,
      declaredHeight: header.height,
      format: header.format,
      declaredBytes: declaredBytes,
      attemptedBytes: attemptBytes,
      allocated: allocated,
      outcome: outcome,
    );
  }

  /// SECURE contrast: enforce a format allowlist and max dimension / byte caps
  /// before allocating anything. The decompression bomb is rejected.
  static DecodeResult decodeSafe(MediaHeader header) {
    if (!allowedFormats.contains(header.format.toLowerCase())) {
      return const DecodeResult(
        accepted: false,
        allocationBytes: 0,
        wouldOom: false,
        reason: 'rejected: unsupported/spoofed format',
      );
    }
    if (header.width <= 0 ||
        header.height <= 0 ||
        header.width > maxDimension ||
        header.height > maxDimension) {
      return const DecodeResult(
        accepted: false,
        allocationBytes: 0,
        wouldOom: false,
        reason: 'rejected: dimensions exceed 8192x8192 cap',
      );
    }
    if (header.byteLength <= 0 || header.byteLength > maxByteLength) {
      return const DecodeResult(
        accepted: false,
        allocationBytes: 0,
        wouldOom: false,
        reason: 'rejected: declared byte length exceeds 64 MiB cap',
      );
    }
    final allocationBytes = header.width * header.height * bytesPerPixel;
    return DecodeResult(
      accepted: true,
      allocationBytes: allocationBytes,
      wouldOom: false,
      reason: 'decoded within caps (${_humanBytes(allocationBytes)})',
    );
  }

  static String _humanBytes(int bytes) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    double value = bytes.toDouble();
    var unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit++;
    }
    return '${value.toStringAsFixed(value >= 100 || unit == 0 ? 0 : 1)} '
        '${units[unit]}';
  }
}

/// A declared media header (offline stand-in for parsed image metadata).
class MediaHeader {
  const MediaHeader({
    required this.width,
    required this.height,
    required this.format,
    required this.byteLength,
  });

  final int width;
  final int height;
  final String format;

  /// The declared on-disk byte length of the media payload.
  final int byteLength;
}

/// Outcome of a simulated decode.
class DecodeResult {
  const DecodeResult({
    required this.accepted,
    required this.allocationBytes,
    required this.wouldOom,
    required this.reason,
  });

  /// Whether the decoder accepted (and would attempt to allocate for) the media.
  final bool accepted;

  /// The buffer size the decoder would allocate, in bytes.
  final int allocationBytes;

  /// Whether that allocation would blow past the safe cap (i.e. OOM the app).
  final bool wouldOom;

  /// Human-readable explanation of the outcome.
  final String reason;

  /// Convenience: the allocation rendered in human-readable units.
  String get humanAllocation => MediaDecoder._humanBytes(allocationBytes);
}

/// Outcome of a real decode attempt that actually tried to allocate the buffer.
class RealDecodeResult {
  const RealDecodeResult({
    required this.declaredWidth,
    required this.declaredHeight,
    required this.format,
    required this.declaredBytes,
    required this.attemptedBytes,
    required this.allocated,
    required this.outcome,
  });

  /// Attacker-declared width.
  final int declaredWidth;

  /// Attacker-declared height.
  final int declaredHeight;

  /// Attacker-declared (possibly spoofed) format.
  final String format;

  /// The full width*height*4 byte count the attacker asked for.
  final int declaredBytes;

  /// The byte count actually requested from the runtime (clamped for the demo).
  final int attemptedBytes;

  /// Whether the (clamped) allocation succeeded.
  final bool allocated;

  /// Human-readable real outcome (succeeded / threw).
  final String outcome;

  String get humanDeclared => MediaDecoder._humanBytes(declaredBytes);
  String get humanAttempted => MediaDecoder._humanBytes(attemptedBytes);
}
