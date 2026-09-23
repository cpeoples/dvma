// DVMA native zero-click media-parse demo - INTENTIONALLY VULNERABLE.
// FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
//
// Real compiled NDK code for zero_click_call_media_parse_sink. Reproduces the
// WeWorm zero-click WeChat VoIP surface in native code: a call-setup media
// frame is reassembled into a fixed heap buffer WHILE THE CALL IS STILL RINGING
// - before the user accepts - and the parser trusts the frame's declared length
// instead of the bytes actually received.
//
//   uint8_t buf[512];
//   memcpy(out, buf, declaredLen);  // declaredLen from attacker, not `received`
//
// A frame whose declared length exceeds the received payload drives an
// out-of-bounds READ past the payload into adjacent reassembly-arena memory
// (CWE-125), with zero user interaction. The Dart layer already models this
// over a Uint8List; this variant performs the over-read in compiled C so it is
// inspectable in the .so. The read length is capped to the arena so the demo
// reports the leak rather than segfaulting.

#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// Fixed reassembly arena the ring-time path fills (mirrors the Dart model).
#define DVMA_ARENA 512

// VULN: reassemble `received` payload bytes into the arena, then hand the
// consumer `declared` bytes - bounded by the arena, never by `received` - so a
// length-lie reads adjacent already-resident bytes the sender never provided.
JNIEXPORT jstring JNICALL
Java_com_dvma_NativeCallMediaProbe_parseOnRing(JNIEnv *env, jobject thiz,
                                               jint declaredLen, jint receivedLen) {
    uint32_t declared = (uint32_t) declaredLen;
    uint32_t received = (uint32_t) receivedLen;
    if (received > DVMA_ARENA) received = DVMA_ARENA;

    uint8_t arena[DVMA_ARENA];
    // Front: the payload actually received on the wire.
    memset(arena, 'P', received);
    // Behind it: initialized-but-unrelated data modelling leaked heap.
    static const char adjacent[] = "SESSION eyJ0..refresh=9f3a-SECRET";
    for (uint32_t i = 0; i < sizeof(adjacent) && received + i < DVMA_ARENA; i++) {
        arena[received + i] = (uint8_t) adjacent[i];
    }

    // VULN: the consumer reads `declared` bytes out of the arena regardless of
    // how few were actually received. Capped at the arena for the demo.
    uint32_t readLen = declared > DVMA_ARENA ? DVMA_ARENA : declared;
    uint32_t leaked = readLen > received ? readLen - received : 0;

    // Capture a printable slice of the over-read region.
    char preview[48];
    size_t p = 0;
    for (uint32_t i = received; i < readLen && p < sizeof(preview) - 1; i++) {
        uint8_t c = arena[i];
        preview[p++] = (c >= 0x20 && c < 0x7f) ? (char) c : '.';
    }
    preview[p] = '\0';

    char report[288];
    snprintf(report, sizeof(report),
             "native ring parse: declaredLen=%u received=%u read=%u "
             "overReadBytes=%u arena=%d leaked=\"%s\"",
             declared, received, readLen, leaked, DVMA_ARENA, preview);

    return (*env)->NewStringUTF(env, report);
}
