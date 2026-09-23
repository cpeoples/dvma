package com.dvma

import android.util.Log
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * JNI bridge to the real vulnerable NDK ring-time media parser (see
 * cpp/dvma_native_callmedia.c). FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * `parseOnRing` calls genuine C that reassembles a call-setup frame into a
 * fixed heap arena WHILE THE CALL IS RINGING and reads the attacker-declared
 * length out of it, never bounded by the bytes actually received
 * (zero_click_call_media_parse_sink, CWE-125). A length-lie over-reads adjacent
 * arena memory with zero user interaction - the WeWorm zero-click VoIP surface
 * - as real compiled C in libdvma_native.so (higher fidelity than the Dart
 * Uint8List model). The channel forwards the declared/received lengths and
 * returns the C-side report including the leaked slice.
 */
class NativeCallMediaProbe {

    /** Real native function implemented in dvma_native_callmedia.c. */
    private external fun parseOnRing(declaredLen: Int, receivedLen: Int): String

    fun register(engine: FlutterEngine) {
        MethodChannel(engine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "parseOnRing" -> {
                        val declared = call.argument<Int>("declaredLen") ?: 0
                        val received = call.argument<Int>("receivedLen") ?: 0
                        val report = runCatching { parseOnRing(declared, received) }
                            .getOrElse { "native call failed: ${it.message}" }
                        Log.w(TAG, report)
                        result.success(report)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    private companion object {
        const val CHANNEL = "dvma/native_callmedia"
        const val TAG = EvidenceStore.TAG

        init {
            System.loadLibrary("dvma_native")
        }
    }
}
