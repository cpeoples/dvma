import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/native_media_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'media_decoder.dart';

/// Unsafe Media / Image Decoding.
///
/// Untrusted image/media bytes are passed straight to a decoder with no
/// type/size/dimension checks, enabling decompression bombs and codec
/// exploitation (Samsung CVE-2025-21043 class).
class UnsafeMediaDecodingScreen extends StatefulWidget {
  const UnsafeMediaDecodingScreen({super.key});

  static const String vulnId = 'unsafe_media_decoding';

  @override
  State<UnsafeMediaDecodingScreen> createState() =>
      _UnsafeMediaDecodingScreenState();
}

class _UnsafeMediaDecodingScreenState extends State<UnsafeMediaDecodingScreen> {
  // A malicious "image": tiny on disk, but declares enormous dimensions and a
  // spoofed format -> a classic decompression bomb.
  static const MediaHeader _bomb = MediaHeader(
    width: 100000,
    height: 100000,
    format: 'x-evil-bomb',
    byteLength: 512, // only 512 bytes on disk, but claims 10 billion pixels
  );

  String? _headerText;
  String? _vulnResult;
  String? _secureResult;
  bool _running = false;

  Future<void> _run() async {
    setState(() => _running = true);
    await Future<void>.delayed(Duration.zero);

    // Prefer the real native decoder (compiled C in libdvma_native.so): a
    // 32-bit width*height*bpp multiply wraps to an undersized malloc while the
    // decode loop writes the real 64-bit count, a genuine heap overflow. Off
    // Android it returns null and we fall back to the offline Dart model.
    final native = await NativeMediaBridge.decodeUnsafe(
      width: _bomb.width,
      height: _bomb.height,
      bpp: MediaDecoder.bytesPerPixel,
    );

    // SECURE: validate dimensions/format/bytes first, never allocates.
    final secure = MediaDecoder.decodeSafe(_bomb);

    if (native != null) {
      await DvmaEvidence.record(
        UnsafeMediaDecodingScreen.vulnId,
        'media-decode',
        'REAL native decode over libdvma_native.so: declared '
            '${_bomb.width}x${_bomb.height} ${_bomb.format}; $native',
      );
      if (!mounted) return;
      setState(() {
        _running = false;
        _headerText =
            'declared: ${_bomb.width}x${_bomb.height} '
            '${_bomb.format}\non-disk bytes: ${_bomb.byteLength}';
        _vulnResult = 'source: REAL native (libdvma_native.so)\n$native';
        _secureResult = 'accepted: ${secure.accepted}\n${secure.reason}';
      });
      return;
    }

    // Offline fallback: actually attempt the attacker-declared allocation.
    final vuln = MediaDecoder.decodeReal(_bomb);

    // The real effect is the attempted (and typically failing) buffer
    // allocation. Mirror declared dims + attempted bytes + outcome.
    await DvmaEvidence.record(
      UnsafeMediaDecodingScreen.vulnId,
      'media-decode',
      'declared: ${vuln.declaredWidth}x${vuln.declaredHeight} '
          '${vuln.format}\n'
          'declared buffer: ${vuln.humanDeclared} (${vuln.declaredBytes} bytes)\n'
          'attempted allocation: ${vuln.humanAttempted} '
          '(${vuln.attemptedBytes} bytes)\n'
          'outcome: ${vuln.outcome}',
    );

    if (!mounted) return;
    setState(() {
      _running = false;
      _headerText =
          'declared: ${_bomb.width}x${_bomb.height} '
          '${_bomb.format}\non-disk bytes: ${_bomb.byteLength}';
      _vulnResult =
          'source: offline model (native lib unavailable)\n'
          'declared buffer: ${vuln.humanDeclared}\n'
          'attempted allocation: ${vuln.humanAttempted}\n'
          'allocated: ${vuln.allocated}\n'
          '${vuln.outcome}';
      _secureResult = 'accepted: ${secure.accepted}\n${secure.reason}';
    });
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: UnsafeMediaDecodingScreen.vulnId,
      title: 'Unsafe Media / Image Decoding',
      difficulty: DvmaDifficulty.medium,
      explanation:
          'Untrusted media is decoded by trusting its declared header verbatim '
          '- no format allowlist, no dimension cap, no byte-length sanity '
          'check. A tiny file can declare 100000x100000 pixels, so the decoder '
          'tries to allocate width*height*4 bytes (tens of GB) and OOMs the '
          'process; spoofed formats reach the codec too (the Samsung '
          'CVE-2025-21043 class). This demo ACTUALLY attempts the declared '
          'pixel-buffer allocation as a Uint8List inside a try/catch (clamped '
          'to a 2 GiB demo ceiling so the host is not hard-crashed) and reports '
          'the real outcome - the thrown OutOfMemoryError/RangeError IS the '
          'observable over-allocation. The secure path enforces an 8192x8192 '
          'cap, a max byte size, and a format allowlist, rejecting the bomb '
          'before allocating anything.',
      children: [
        DemoActionButton(
          label: _running ? 'Decoding…' : 'Decode untrusted image',
          onPressed: _running ? () {} : () => _run(),
        ),
        if (_headerText != null)
          EvidencePanel(label: 'attacker-declared header', value: _headerText!),
        if (_vulnResult != null)
          EvidencePanel(
            label: 'unchecked decoder (native heap overflow / real allocation)',
            value: _vulnResult!,
          ),
        if (_secureResult != null)
          EvidencePanel(
            label: 'validating decoder (bomb rejected)',
            value: _secureResult!,
          ),
      ],
    );
  }
}
