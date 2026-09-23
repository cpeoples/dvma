package com.dvma

import android.util.Log
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * JNI bridge to the real vulnerable NDK library (see src/main/cpp).
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * `unsafeCopy` calls a genuine C `strcpy` into a fixed 16-byte stack buffer
 * with no bounds check (native_code_memory_bugs, CWE-120 / CWE-787). The bug is
 * real and compiled into libdvma_native.so - inspectable with ghidra/gdb/frida
 * - not a Dart model. The Kotlin channel just forwards the caller's input and
 * returns the C-side report describing whether the adjacent canary was
 * clobbered.
 */
class NativeMemoryProbe {

    /** Real native function implemented in dvma_native_memory.c. */
    private external fun unsafeCopy(input: String): String

    fun register(engine: FlutterEngine) {
        MethodChannel(engine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "unsafeCopy" -> {
                        val input = call.argument<String>("input") ?: ""
                        val report = runCatching { unsafeCopy(input) }
                            .getOrElse { "native call failed: ${it.message}" }
                        Log.w(TAG, report)
                        result.success(report)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    private companion object {
        const val CHANNEL = "dvma/native_memory"
        const val TAG = EvidenceStore.TAG

        init {
            System.loadLibrary("dvma_native")
        }
    }
}
