# DVMA native memory-safety demo - INTENTIONALLY VULNERABLE.
# FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
#
# Builds the real NDK library exercised by native_code_memory_bugs and the
# other native memory-safety modules (unsafe_media_decoding,
# proximity_transfer_unsafe_parsing, zero_click_call_media_parse_sink). The
# vulnerable code is compiled with stack-protector OFF and _FORTIFY_SOURCE=0
# so the overflows/over-reads are not masked by hardening - the whole point is
# that genuine memory bugs ship in the .so for ghidra/gdb/frida analysis.
cmake_minimum_required(VERSION 3.18.1)
project(dvma_native)

add_library(dvma_native SHARED
    dvma_native_memory.c
    dvma_native_media.c
    dvma_native_proximity.c
    dvma_native_callmedia.c)

target_compile_options(dvma_native PRIVATE
    -fno-stack-protector
    -U_FORTIFY_SOURCE
    -D_FORTIFY_SOURCE=0
    -Wno-deprecated-declarations)

find_library(log-lib log)
target_link_libraries(dvma_native ${log-lib})
