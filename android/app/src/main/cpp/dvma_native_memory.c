// DVMA native memory-safety demo - INTENTIONALLY VULNERABLE.
// FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
//
// This is a REAL, compiled NDK library (not a Dart model). It contains a
// classic unbounded copy into a fixed stack buffer so the module
// `native_code_memory_bugs` exercises genuine native memory unsafety that
// ghidra/gdb/frida can inspect on the built .so:
//
//   char buf[16];
//   strcpy(buf, input);   // no bounds check -> stack buffer overflow
//
// The function reads back an adjacent "saved return address" canary placed
// right after the buffer so the caller can observe that oversized input
// clobbered it. AddressSanitizer (if the build enables it) traps the overflow;
// a normal build corrupts the adjacent slot. Either way the bug is real and
// lives in native code, matching CWE-120 / CWE-787.

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// A fixed-size stack layout: the vulnerable buffer immediately followed by a
// 4-byte canary that stands in for a saved return address / frame slot.
typedef struct {
    char buf[16];
    unsigned char canary[4];
} frame_t;

// VULN: copies the caller-supplied string into buf[16] with strcpy and NO
// bounds check. Oversized input runs past buf into the canary (and beyond) -
// a genuine stack buffer overflow in compiled native code.
JNIEXPORT jstring JNICALL
Java_com_dvma_NativeMemoryProbe_unsafeCopy(JNIEnv *env, jobject thiz, jstring input) {
    const char *in = (*env)->GetStringUTFChars(env, input, NULL);

    frame_t frame;
    memset(frame.buf, 0, sizeof(frame.buf));
    // A known canary value so an overwrite is observable.
    frame.canary[0] = 0xAA;
    frame.canary[1] = 0xBB;
    frame.canary[2] = 0xCC;
    frame.canary[3] = 0xDD;

    // The vulnerable call. If `in` is longer than 15 chars + NUL it overflows.
    strcpy(frame.buf, in);

    size_t in_len = strlen(in);
    int overflowed = in_len >= sizeof(frame.buf);

    char report[256];
    snprintf(report, sizeof(report),
             "native strcpy: bufferSize=%zu inputLength=%zu overflowed=%s "
             "canaryAfterCopy=%02X%02X%02X%02X (was AABBCCDD)",
             sizeof(frame.buf), in_len, overflowed ? "true" : "false",
             frame.canary[0], frame.canary[1], frame.canary[2], frame.canary[3]);

    (*env)->ReleaseStringUTFChars(env, input, in);
    return (*env)->NewStringUTF(env, report);
}

// A heap record with an inline function-pointer-ish tag: after free() the chunk
// is returned to the allocator, but a dangling pointer still references it.
typedef struct {
    unsigned int tag;   // 0xFEEDFACE while live
    char note[24];
} record_t;

// VULN: a second native memory-safety class - heap use-after-free plus double
// free (CWE-416 / CWE-415). The record is freed, then still read and written
// through the dangling pointer, and finally freed a second time. The allocator
// metadata / freelist is corrupted; on a normal build this is exploitable (a
// reallocation of the same chunk lets an attacker control `tag`). ASan traps
// it; a plain build silently corrupts the heap. `writeAfterFree` toggles the
// dangling write so the caller can compare a UAF read vs a UAF write+double
// free.
JNIEXPORT jstring JNICALL
Java_com_dvma_NativeHeapProbe_useAfterFree(JNIEnv *env, jobject thiz,
                                           jboolean writeAfterFree) {
    record_t *rec = (record_t *) malloc(sizeof(record_t));
    if (rec == NULL) return (*env)->NewStringUTF(env, "malloc failed");
    rec->tag = 0xFEEDFACE;
    strcpy(rec->note, "live session record");

    // The record is released back to the allocator...
    free(rec);

    // ...but `rec` is still used. Reading through it is a use-after-free.
    unsigned int tagAfterFree = rec->tag; // dangling read

    int wroteAfterFree = 0;
    if (writeAfterFree) {
        // Dangling write: clobber a freed chunk the allocator may have handed
        // out again. This is the primitive an attacker turns into control.
        rec->tag = 0x41414141;
        strcpy(rec->note, "attacker-controlled after free");
        wroteAfterFree = 1;
    }

    // Freeing the same pointer twice corrupts the freelist (double free).
    free(rec);

    char report[224];
    snprintf(report, sizeof(report),
             "native UAF: recordSize=%zu tagWas=%08X tagAfterFree=%08X "
             "wroteAfterFree=%s doubleFreed=true",
             sizeof(record_t), 0xFEEDFACEu, tagAfterFree,
             wroteAfterFree ? "true" : "false");

    return (*env)->NewStringUTF(env, report);
}
