package com.dvma

import android.util.Log
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * JNI bridge to the real vulnerable NDK TLV parser (see cpp/dvma_native_proximity.c).
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * `parseTlv` calls genuine C that copies a pre-auth proximity payload out of a
 * received heap buffer using the attacker-declared length field, never bounded
 * by the bytes actually received (proximity_transfer_unsafe_parsing, CWE-125 /
 * CWE-787). A length-lie reads adjacent heap the sender never provided - a real
 * over-read compiled into libdvma_native.so, inspectable with ghidra/gdb/frida
 * (not a Dart model). The channel forwards the declared/received lengths and
 * returns the C-side report including a slice of what leaked.
 */
class NativeProximityProbe {

    /** Real native function implemented in dvma_native_proximity.c. */
    private external fun parseTlv(declaredLen: Int, payloadLen: Int): String

    fun register(engine: FlutterEngine) {
        MethodChannel(engine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "parseTlv" -> {
                        val declared = call.argument<Int>("declaredLen") ?: 0
                        val payload = call.argument<Int>("payloadLen") ?: 0
                        val report = runCatching { parseTlv(declared, payload) }
                            .getOrElse { "native call failed: ${it.message}" }
                        Log.w(TAG, report)
                        result.success(report)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    private companion object {
        const val CHANNEL = "dvma/native_proximity"
        const val TAG = EvidenceStore.TAG

        init {
            System.loadLibrary("dvma_native")
        }
    }
}
