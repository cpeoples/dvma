// DVMA native memory-safety demo (iOS) - INTENTIONALLY VULNERABLE.
// FOR AUTHORIZED SECURITY-TRAINING USE ONLY. See dvma_native_memory.h.

#include "dvma_native_memory.h"
#include <string.h>
#include <stdio.h>

typedef struct {
    char buf[16];
    unsigned char canary[4];
} dvma_frame_t;

void dvma_unsafe_copy(const char *input, char *out, unsigned long out_len) {
    dvma_frame_t frame;
    memset(frame.buf, 0, sizeof(frame.buf));
    frame.canary[0] = 0xAA;
    frame.canary[1] = 0xBB;
    frame.canary[2] = 0xCC;
    frame.canary[3] = 0xDD;

    // VULN: unbounded copy into buf[16]. Oversized input overruns into canary.
    strcpy(frame.buf, input);

    unsigned long in_len = strlen(input);
    int overflowed = in_len >= sizeof(frame.buf);
    snprintf(out, out_len,
             "native strcpy: bufferSize=%lu inputLength=%lu overflowed=%s "
             "canaryAfterCopy=%02X%02X%02X%02X (was AABBCCDD)",
             (unsigned long)sizeof(frame.buf), in_len,
             overflowed ? "true" : "false",
             frame.canary[0], frame.canary[1], frame.canary[2], frame.canary[3]);
}
