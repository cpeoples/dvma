import 'package:flutter/material.dart';

import '../../../core/evidence_sink.dart';
import '../../../core/native/native_heap_bridge.dart';
import '../../../core/native/native_memory_bridge.dart';
import '../../../core/theme/dvma_colors.dart';
import '../../../core/vuln_demo_scaffold.dart';
import 'native_buffer_sim.dart';

/// Native Code Memory Bugs (JNI buffer overflow).
///
/// On Android this calls a real compiled C `strcpy` into a fixed 16-byte stack
/// buffer (libdvma_native.so); off-Android it falls back to an offline model.
class NativeCodeMemoryBugsScreen extends StatefulWidget {
  const NativeCodeMemoryBugsScreen({super.key});

  static const String vulnId = 'native_code_memory_bugs';

  @override
  State<NativeCodeMemoryBugsScreen> createState() =>
      _NativeCodeMemoryBugsScreenState();
}

class _NativeCodeMemoryBugsScreenState
    extends State<NativeCodeMemoryBugsScreen> {
  final _input = TextEditingController(
    text: 'AAAAAAAAAAAAAAAAAAAAAAAA', // > 16 bytes
  );
  String? _result;
  String? _uafResult;

  Future<void> _run() async {
    // Prefer the real native strcpy (compiled C in libdvma_native.so); fall
    // back to the offline model on iOS/desktop/flutter test.
    final native = await NativeMemoryBridge.unsafeCopy(_input.text);
    if (native != null) {
      await DvmaEvidence.record(
        NativeCodeMemoryBugsScreen.vulnId,
        'buffer-overflow',
        'REAL native strcpy over libdvma_native.so: $native',
      );
      if (!mounted) return;
      setState(
        () => _result = 'source: REAL native (libdvma_native.so)\n$native',
      );
      return;
    }
    final sim = NativeBufferSim.unsafeStrcpy(_input.text);
    await DvmaEvidence.record(
      NativeCodeMemoryBugsScreen.vulnId,
      'buffer-overflow',
      'offline model: bufferSize=${sim['bufferSize']} '
          'inputLength=${sim['inputLength']} overflowed=${sim['overflowed']} '
          'returnAddrSlotClobbered=${sim['returnAddrSlot']}',
    );
    if (!mounted) return;
    setState(
      () => _result =
          'source: offline model (native lib unavailable)\n'
          'bufferSize = ${sim['bufferSize']}\n'
          'inputLength = ${sim['inputLength']}\n'
          'overflowed = ${sim['overflowed']}\n'
          'return-address slot clobbered with = ${sim['returnAddrSlot']}',
    );
  }

  /// Second real native bug class: a heap use-after-free + double free. Only
  /// available on Android (compiled C in libdvma_native.so); off-device the
  /// button reports that the native library is unavailable, keeping the demo
  /// testable without shipping the effect in Dart.
  Future<void> _runUaf() async {
    final native = await NativeHeapBridge.useAfterFree(writeAfterFree: true);
    if (native != null) {
      await DvmaEvidence.record(
        NativeCodeMemoryBugsScreen.vulnId,
        'use-after-free',
        'REAL native use-after-free + double free over libdvma_native.so: '
            '$native',
      );
      if (!mounted) return;
      setState(
        () => _uafResult = 'source: REAL native (libdvma_native.so)\n$native',
      );
      return;
    }
    if (!mounted) return;
    setState(
      () => _uafResult =
          'native library unavailable (heap UAF ships only in the Android .so)',
    );
  }

  @override
  Widget build(BuildContext context) {
    return VulnDemoScaffold(
      vulnId: NativeCodeMemoryBugsScreen.vulnId,
      title: 'Native Code Memory Bugs',
      difficulty: DvmaDifficulty.hard,
      explanation:
          'A JNI routine does strcpy into a fixed 16-byte stack buffer with no '
          'bounds check, so oversized input overwrites the adjacent canary '
          '(classic stack smash). A second routine frees a heap record and '
          'keeps using it through the dangling pointer before freeing it again '
          '(use-after-free + double free). On a device both run REAL compiled C '
          'in libdvma_native.so - inspectable with ghidra/gdb/frida - and '
          'report what was clobbered; off-device the strcpy falls back to an '
          'offline model so the demo stays testable.',
      children: [
        TextField(
          controller: _input,
          decoration: const InputDecoration(
            labelText: 'input copied to buf[16]',
          ),
        ),
        DemoActionButton(label: 'Call native strcpy', onPressed: _run),
        if (_result != null)
          EvidencePanel(label: 'memory after copy', value: _result!),
        DemoActionButton(
          label: 'Trigger heap use-after-free',
          onPressed: _runUaf,
        ),
        if (_uafResult != null)
          EvidencePanel(label: 'heap after use-after-free', value: _uafResult!),
      ],
    );
  }
}
