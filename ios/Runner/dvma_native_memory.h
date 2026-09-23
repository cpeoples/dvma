// DVMA native memory-safety demo (iOS) - INTENTIONALLY VULNERABLE.
// FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
//
// Parity with the Android NDK library (android/app/src/main/cpp): a REAL
// compiled C stack buffer overflow that ships in the Runner Mach-O so
// native_code_memory_bugs exercises genuine native memory unsafety a researcher
// can inspect with Hopper / lldb / frida on iOS too (CWE-120 / CWE-787).

#ifndef DVMA_NATIVE_MEMORY_H
#define DVMA_NATIVE_MEMORY_H

// Copies `input` into a fixed 16-byte stack buffer with strcpy and NO bounds
// check, then writes a report describing whether the adjacent canary slot was
// clobbered into `out` (capacity `out_len`). The overflow is real; `out` only
// carries the human-readable result back to Swift.
void dvma_unsafe_copy(const char *input, char *out, unsigned long out_len);

#endif
