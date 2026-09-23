// DVMA native proximity-parse demo - INTENTIONALLY VULNERABLE.
// FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
//
// Real compiled NDK code for proximity_transfer_unsafe_parsing. A pre-auth
// proximity payload (AirDrop / Quick Share) is parsed as a TLV record:
//
//   [ 1 byte type ][ 2 byte big-endian length ][ length bytes value ]
//
// The parser trusts the declared length field and copies that many bytes out of
// the received buffer into a fixed output buffer, WITHOUT checking it against
// the number of bytes actually received. A record that declares a length larger
// than the payload drives an out-of-bounds READ past the end of the input
// (CWE-125), leaking adjacent heap; a length larger than the destination is
// also a write overflow (CWE-787). This is the AirDrop / Quick Share
// proximity-protocol over-read class - no pairing required.
//
// The received buffer is heap-allocated with a known "adjacent" secret placed
// immediately after the real payload, so the over-read visibly captures bytes
// the sender never provided. The copy length is capped so the demo reports the
// leak instead of walking off the mapping.

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Fixed destination the parser reassembles the value into.
#define DVMA_TLV_DEST 64
// Ceiling on how far past the payload we actually read, so the demo survives.
#define DVMA_OVERREAD_CAP 128

// Parses one TLV record. `payloadLen` is the number of value bytes actually
// received; `declaredLen` is the attacker-controlled length field. VULN: the
// copy is bounded by `declaredLen`, never by `payloadLen`, so a lie in the
// header reads past the received bytes into adjacent heap.
JNIEXPORT jstring JNICALL
Java_com_dvma_NativeProximityProbe_parseTlv(JNIEnv *env, jobject thiz,
                                            jint declaredLen, jint payloadLen) {
    uint32_t declared = (uint32_t) declaredLen;
    uint32_t payload = (uint32_t) payloadLen;

    // Heap-allocate the received region: the payload, then an adjacent secret
    // that the sender never transmitted - an over-read exposes it.
    static const char adjacent[] = "ADJ-HEAP token=eyJ0..refresh=9f3a-SECRET";
    size_t adjLen = sizeof(adjacent); // includes NUL
    uint8_t *recv = (uint8_t *) malloc(payload + adjLen);
    if (recv == NULL) return (*env)->NewStringUTF(env, "malloc failed");
    memset(recv, 'A', payload);          // the bytes actually received
    memcpy(recv + payload, adjacent, adjLen); // heap neighbour behind them

    uint8_t dest[DVMA_TLV_DEST];
    memset(dest, 0, sizeof(dest));

    // VULN: copy `declared` bytes out of `recv` bounded only by a demo cap -
    // NOT by `payload` (over-read) and NOT by sizeof(dest) (over-write).
    uint32_t copyLen = declared;
    if (copyLen > payload + DVMA_OVERREAD_CAP) copyLen = payload + DVMA_OVERREAD_CAP;

    uint32_t leaked = 0;
    for (uint32_t i = 0; i < copyLen; i++) {
        uint8_t byte = recv[i];             // OOB read once i >= payload
        if (i < sizeof(dest)) dest[i] = byte; // OOB write avoided past dest cap
        if (i >= payload) leaked++;
    }

    // Surface a printable slice of what leaked from behind the payload.
    char leakPreview[48];
    size_t p = 0;
    for (uint32_t i = payload; i < copyLen && p < sizeof(leakPreview) - 1; i++) {
        uint8_t c = recv[i];
        leakPreview[p++] = (c >= 0x20 && c < 0x7f) ? (char) c : '.';
    }
    leakPreview[p] = '\0';

    char report[320];
    snprintf(report, sizeof(report),
             "native TLV: declaredLen=%u payloadLen=%u copied=%u "
             "overReadBytes=%u destSize=%d leaked=\"%s\"",
             declared, payload, copyLen, leaked, DVMA_TLV_DEST, leakPreview);

    free(recv);
    return (*env)->NewStringUTF(env, report);
}
