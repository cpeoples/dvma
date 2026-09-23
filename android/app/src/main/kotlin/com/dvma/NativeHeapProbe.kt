package com.dvma

import android.util.Log
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * JNI bridge to a second real vulnerable NDK memory bug (see the tail of
 * cpp/dvma_native_memory.c). FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * `useAfterFree` calls genuine C that frees a heap record, keeps using it
 * through the dangling pointer, then frees it a second time
 * (native_code_memory_bugs, CWE-416 / CWE-415). This broadens the module beyond
 * the stack strcpy overflow with a heap use-after-free + double free compiled
 * into libdvma_native.so - inspectable with ghidra/gdb/frida, not a Dart model.
 * The channel returns the C-side report describing the dangling read/write and
 * the double free.
 */
class NativeHeapProbe {

    /** Real native function implemented in dvma_native_memory.c. */
    private external fun useAfterFree(writeAfterFree: Boolean): String

    fun register(engine: FlutterEngine) {
        MethodChannel(engine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "useAfterFree" -> {
                        val write = call.argument<Boolean>("writeAfterFree") ?: false
                        val report = runCatching { useAfterFree(write) }
                            .getOrElse { "native call failed: ${it.message}" }
                        Log.w(TAG, report)
                        result.success(report)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    private companion object {
        const val CHANNEL = "dvma/native_heap"
        const val TAG = EvidenceStore.TAG

        init {
            System.loadLibrary("dvma_native")
        }
    }
}
