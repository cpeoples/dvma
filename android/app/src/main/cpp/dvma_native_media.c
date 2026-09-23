// DVMA native media-decode demo - INTENTIONALLY VULNERABLE.
// FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
//
// Real compiled NDK code for unsafe_media_decoding. A decoder trusts an
// attacker-declared width/height/bpp from an image header and computes the
// pixel-buffer size as a 32-bit multiply:
//
//   uint32_t need = width * height * bpp;   // silently wraps mod 2^32
//   uint8_t *buf  = malloc(need);           // undersized when it wraps
//   memset(buf, 0xff, width * height * bpp) // writes the *real* size -> heap overflow
//
// When width*height*bpp exceeds 2^32 the multiply wraps to a small value, so
// malloc hands back a tiny chunk while the decode loop still writes the full
// (64-bit) declared pixel count. That is the classic integer-overflow ->
// undersized allocation -> heap buffer overflow (CWE-190 -> CWE-122 / CWE-787),
// the Samsung CVE-2025-21043 codec class. The write is capped at a small demo
// ceiling so the process reports the corruption instead of dying outright, but
// the undersized malloc and the out-of-bounds store are genuine.

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// How many bytes past the (undersized) allocation we actually store before
// stopping. Keeps the demo from segfaulting on every run while still performing
// a real out-of-bounds write into heap-adjacent memory.
#define DVMA_OOB_WRITE_CAP 4096

// VULN: trust attacker-declared dimensions, size the buffer with a 32-bit
// multiply that wraps, malloc that wrapped size, then decode (write) the real
// 64-bit pixel count into it - overrunning the heap chunk.
JNIEXPORT jstring JNICALL
Java_com_dvma_NativeMediaProbe_decodeUnsafe(JNIEnv *env, jobject thiz,
                                            jint width, jint height, jint bpp) {
    uint32_t w = (uint32_t) width;
    uint32_t h = (uint32_t) height;
    uint32_t b = (uint32_t) bpp;

    // The size the codec THINKS it needs - a 32-bit multiply, so it wraps.
    uint32_t allocSize = w * h * b;
    // The size actually implied by the header, computed in 64-bit (no wrap).
    uint64_t realSize = (uint64_t) w * (uint64_t) h * (uint64_t) b;

    uint8_t *buf = (uint8_t *) malloc(allocSize);
    if (buf == NULL) {
        char oom[128];
        snprintf(oom, sizeof(oom),
                 "malloc(%u) failed for declared %llu bytes",
                 allocSize, (unsigned long long) realSize);
        return (*env)->NewStringUTF(env, oom);
    }

    // VULN: the decode loop fills `realSize` bytes even though only `allocSize`
    // were reserved. Bounded to the demo cap so we can report the overflow.
    uint64_t toWrite = realSize;
    if (toWrite > allocSize + DVMA_OOB_WRITE_CAP) {
        toWrite = allocSize + DVMA_OOB_WRITE_CAP;
    }
    for (uint64_t i = 0; i < toWrite; i++) {
        buf[i] = 0xFF; // out-of-bounds once i >= allocSize
    }

    uint64_t overflowBytes = toWrite > allocSize ? toWrite - allocSize : 0;
    int wrapped = realSize != (uint64_t) allocSize;

    char report[320];
    snprintf(report, sizeof(report),
             "native decode: %ux%u x%ubpp declaredBytes=%llu allocSize=%u "
             "(32-bit multiply %s) wroteBytes=%llu heapOverflowBytes=%llu",
             w, h, b, (unsigned long long) realSize, allocSize,
             wrapped ? "WRAPPED" : "no wrap",
             (unsigned long long) toWrite, (unsigned long long) overflowBytes);

    free(buf);
    return (*env)->NewStringUTF(env, report);
}
