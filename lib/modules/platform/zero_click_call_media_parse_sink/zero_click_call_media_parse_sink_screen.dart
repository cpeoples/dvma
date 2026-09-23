import 'dart:typed_data';

import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/native_callmedia_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'call_media_parser.dart';

/// Zero-Click Media Parse Before User Accept (VoIP-ring class).
///
/// Reproduces the WeWorm zero-click WeChat VoIP surface: call-setup media is
/// parsed while ringing, and an attacker-declared length overruns the fixed
/// reassembly buffer with no user interaction.
class ZeroClickCallMediaParseSinkScreen extends StatefulWidget {
  const ZeroClickCallMediaParseSinkScreen({super.key});

  static const String vulnId = 'zero_click_call_media_parse_sink';

  @override
  State<ZeroClickCallMediaParseSinkScreen> createState() =>
      _ZeroClickCallMediaParseSinkScreenState();
}

class _ZeroClickCallMediaParseSinkScreenState
    extends State<ZeroClickCallMediaParseSinkScreen> {
  String? _result;

  Future<void> _run() async {
    // Attacker frame: declares the full buffer length but ships only a small
    // payload, the classic length-lie that over-reads adjacent memory.
    final frame = CallMediaParser.frame(
      declaredLength: CallMediaParser.reassemblyBufferBytes,
      payload: Uint8List(16),
    );
    final onRing = await CallMediaParser.parseOnRing(frame);
    final secure = CallMediaParser.secureParse(frame, userAccepted: false);

    // Higher-fidelity variant: perform the same ring-time over-read in real
    // compiled C (libdvma_native.so) when on Android. Off Android this returns
    // null and only the Dart Uint8List over-read above is shown.
    final native = await NativeCallMediaBridge.parseOnRing(
      declaredLen: CallMediaParser.reassemblyBufferBytes,
      receivedLen: 16,
    );

    if (!mounted) return;
    setState(
      () => _result =
          'ring-time parse (vulnerable):\n'
          '  parsed before accept: ${onRing.parsedBeforeAccept}\n'
          '  declared=${onRing.declaredLength} payload=${onRing.actualLength} '
          'over-read=${onRing.leakedBytes} bytes\n'
          '  overflowed: ${onRing.overflowed} - ${onRing.reason}\n'
          '${onRing.artifactPath == null ? "" : "  artifact: ${onRing.artifactPath}\n"}'
          '${native == null ? "" : "\nnative ring parse (libdvma_native.so):\n  $native\n"}'
          '\nhardened parse: ${secure.reason}',
    );
    if (onRing.overflowed && onRing.parsedBeforeAccept) {
      DvmaEvidence.record(
        ZeroClickCallMediaParseSinkScreen.vulnId,
        'zero-click-parse-overread',
        'ring-time media reassembly read ${onRing.leakedBytes} bytes past a '
            '${onRing.actualLength}-byte payload (declared '
            '${onRing.declaredLength}) before the user accepted the call - '
            'zero-click over-read'
            '${onRing.artifactPath == null ? "" : "; leaked region written to ${onRing.artifactPath}"}',
      );
    }
    if (native != null) {
      DvmaEvidence.record(
        ZeroClickCallMediaParseSinkScreen.vulnId,
        'zero-click-native-overread',
        'REAL native ring-time over-read over libdvma_native.so: $native',
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: ZeroClickCallMediaParseSinkScreen.vulnId,
      title: 'Zero-Click Media Parse Before Accept',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'Call-setup media is reassembled into a fixed buffer while the call '
          'is still ringing - before the user accepts - and the parser trusts '
          'an attacker-declared length field instead of the bytes actually '
          'present. A frame whose declared length exceeds the buffer drives an '
          'out-of-bounds write with zero user interaction. This reproduces the '
          'WeWorm zero-click WeChat VoIP surface as an offline, deterministic '
          'bounds check over an in-memory buffer.',
      children: [
        DemoActionButton(
          label: 'Deliver malicious ring frame',
          onPressed: _run,
        ),
        if (_result != null)
          EvidencePanel(label: 'ring-time parse outcome', value: _result!),
      ],
    );
  }
}
