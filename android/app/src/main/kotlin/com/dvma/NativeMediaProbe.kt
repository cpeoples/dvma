package com.dvma

import android.util.Log
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * JNI bridge to the real vulnerable NDK media decoder (see cpp/dvma_native_media.c).
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * `decodeUnsafe` calls genuine C that sizes a pixel buffer with a 32-bit
 * `width * height * bpp` multiply (unsafe_media_decoding, CWE-190 -> CWE-122).
 * Attacker-declared dimensions wrap the multiply, so malloc returns an
 * undersized chunk while the decode loop writes the real 64-bit pixel count -
 * a genuine integer-overflow heap buffer overflow compiled into
 * libdvma_native.so, inspectable with ghidra/gdb/frida (not a Dart model). The
 * channel forwards the declared header fields and returns the C-side report.
 */
class NativeMediaProbe {

    /** Real native function implemented in dvma_native_media.c. */
    private external fun decodeUnsafe(width: Int, height: Int, bpp: Int): String

    fun register(engine: FlutterEngine) {
        MethodChannel(engine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "decodeUnsafe" -> {
                        val width = call.argument<Int>("width") ?: 0
                        val height = call.argument<Int>("height") ?: 0
                        val bpp = call.argument<Int>("bpp") ?: 4
                        val report = runCatching { decodeUnsafe(width, height, bpp) }
                            .getOrElse { "native call failed: ${it.message}" }
                        Log.w(TAG, report)
                        result.success(report)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    private companion object {
        const val CHANNEL = "dvma/native_media"
        const val TAG = EvidenceStore.TAG

        init {
            System.loadLibrary("dvma_native")
        }
    }
}
