/// Native buffer-overflow simulation.
///
/// INTENTIONALLY VULNERABLE (CWE-120 / CWE-787): models a classic C routine
///
/// ```c
/// char buf[16];
/// strcpy(buf, input);   // no bounds check
/// ```
///
/// The real bug lives in JNI/FFI native code (ghidra/gdb/frida territory), but
/// this Dart model reproduces the observable effect, writing past a fixed-size
/// buffer clobbers adjacent memory, so it is demonstrable and testable without
/// shipping native code (we do not edit android/ios).
class NativeBufferSim {
  NativeBufferSim._();

  /// Fixed stack buffer size, as in the vulnerable C function.
  static const int bufferSize = 16;

  /// Copies [input] into a [bufferSize]-byte buffer with no bounds check.
  /// Returns a report describing whether adjacent memory (a "return address"
  /// canary slot placed right after the buffer) was overwritten.
  static Map<String, Object?> unsafeStrcpy(String input) {
    // buffer + a 4-byte "saved return address" placed immediately after it.
    final memory = List<int>.filled(bufferSize + 4, 0);
    final bytes = input.codeUnits;
    var overflowed = false;
    for (var i = 0; i < bytes.length; i++) {
      if (i >= memory.length) {
        // Past even the adjacent slot: in real code this is arbitrary write.
        overflowed = true;
        break;
      }
      if (i >= bufferSize) overflowed = true; // wrote into the return-addr slot
      memory[i] = bytes[i];
    }
    final clobbered = memory.sublist(bufferSize, bufferSize + 4);
    return {
      'bufferSize': bufferSize,
      'inputLength': bytes.length,
      'overflowed': overflowed,
      'returnAddrSlot': clobbered,
    };
  }
}
