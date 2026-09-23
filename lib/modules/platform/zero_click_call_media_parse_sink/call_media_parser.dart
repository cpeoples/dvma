import 'dart:io';
import 'dart:typed_data';

import '../../../core/evidence_sink.dart';

/// The result of feeding a call-setup media frame to the parser.
class CallParseResult {
  CallParseResult({
    required this.parsedBeforeAccept,
    required this.userAccepted,
    required this.declaredLength,
    required this.actualLength,
    required this.overflowed,
    required this.leakedBytes,
    required this.artifactPath,
    required this.reason,
  });

  /// True when the frame was parsed while the call was still ringing.
  final bool parsedBeforeAccept;

  /// Whether the user ever accepted the call.
  final bool userAccepted;

  /// The length the attacker declared in the frame header.
  final int declaredLength;

  /// The bytes actually present in the payload.
  final int actualLength;

  /// True when the parse read past the payload into adjacent memory.
  final bool overflowed;

  /// How many bytes past the payload the length-lie caused to be read.
  final int leakedBytes;

  /// The real on-disk artifact holding the over-read region, when written.
  final String? artifactPath;
  final String reason;
}

/// Zero-click media parse before user accept (VoIP-ring class).
///
/// INTENTIONALLY VULNERABLE (CWE-20 / CWE-125): reproduces the app-layer pattern
/// behind the WeWorm zero-click WeChat VoIP worm (Aug 2026). Call-setup media is
/// reassembled *while the call is still ringing*, before the user accepts, and
/// the parser trusts an attacker-declared length field instead of the bytes
/// actually present. A frame whose declared length exceeds the payload drives an
/// out-of-bounds READ over adjacent buffer memory (the initialized-but-unrelated
/// region that models leaked heap), exactly the zero-user-interaction surface
/// the worm abused.
///
/// The over-read is performed over a real [Uint8List] arena and the leaked
/// region is written to a real, adb-/simctl-pullable file via [DvmaEvidence], so
/// the artifact is genuinely on disk, not just a boolean. No real process
/// memory is corrupted; the arena stands in for the reassembly heap.
class CallMediaParser {
  /// Fixed reassembly buffer the ring-time path writes incoming media into.
  static const int reassemblyBufferBytes = 512;

  /// Builds a call-setup frame: a 4-byte big-endian declared-length header
  /// followed by [payload]. An attacker can lie in the header.
  static Uint8List frame({
    required int declaredLength,
    required Uint8List payload,
  }) {
    final out = BytesBuilder();
    out.add([
      (declaredLength >> 24) & 0xff,
      (declaredLength >> 16) & 0xff,
      (declaredLength >> 8) & 0xff,
      declaredLength & 0xff,
    ]);
    out.add(payload);
    return out.toBytes();
  }

  static int _declaredLength(Uint8List f) =>
      (f[0] << 24) | (f[1] << 16) | (f[2] << 8) | f[3];

  /// VULN: parses the frame as soon as it arrives (call still ringing), reading
  /// `declaredLength` bytes out of the reassembly arena even though only the
  /// payload was received, so the copy runs past the payload into adjacent
  /// (attacker-observable) memory, and the over-read region is persisted.
  static Future<CallParseResult> parseOnRing(Uint8List frameBytes) async {
    final declared = _declaredLength(frameBytes);
    final payload = frameBytes.sublist(4);
    final actual = payload.length;

    // The reassembly arena: payload at the front, "adjacent" already-resident
    // data behind it (models heap neighbours the over-read would expose).
    final arena = Uint8List(reassemblyBufferBytes);
    arena.setRange(0, actual.clamp(0, reassemblyBufferBytes), payload);
    const adjacent = 'ADJACENT-HEAP session=eyJ0..refresh=9f3a-SECRET';
    final adjBytes = adjacent.codeUnits;
    for (var i = 0; i < adjBytes.length && actual + i < arena.length; i++) {
      arena[actual + i] = adjBytes[i];
    }

    // VULN: copy `declared` bytes, bounded only by the arena, not by `actual`.
    final readLen = declared.clamp(0, reassemblyBufferBytes);
    final leaked = readLen > actual ? readLen - actual : 0;
    final overflowed = leaked > 0;

    String? artifactPath;
    if (overflowed) {
      final base = await DvmaEvidence.writableBaseDir();
      if (base != null) {
        final f = File('${base.path}/zero_click_overread.bin');
        await f.writeAsBytes(arena.sublist(actual, readLen));
        artifactPath = f.path;
      }
    }
    return CallParseResult(
      parsedBeforeAccept: true,
      userAccepted: false,
      declaredLength: declared,
      actualLength: actual,
      overflowed: overflowed,
      leakedBytes: leaked,
      artifactPath: artifactPath,
      reason: overflowed
          ? 'declared $declared > payload $actual: read $leaked bytes past the '
                'payload during ring-time reassembly (zero-click over-read)'
          : 'declared length within payload',
    );
  }

  /// A hardened client defers media parsing until after the user accepts, and
  /// bounds every read by the bytes actually present.
  static CallParseResult secureParse(
    Uint8List frameBytes, {
    required bool userAccepted,
  }) {
    final actual = frameBytes.length - 4;
    if (!userAccepted) {
      return CallParseResult(
        parsedBeforeAccept: false,
        userAccepted: false,
        declaredLength: 0,
        actualLength: actual,
        overflowed: false,
        leakedBytes: 0,
        artifactPath: null,
        reason: 'media not parsed until the user accepts the call',
      );
    }
    final declared = _declaredLength(frameBytes);
    final copy = declared.clamp(0, actual);
    return CallParseResult(
      parsedBeforeAccept: false,
      userAccepted: true,
      declaredLength: declared,
      actualLength: actual,
      overflowed: false,
      leakedBytes: 0,
      artifactPath: null,
      reason: 'read $copy bytes, bounded by the actual payload length',
    );
  }
}
