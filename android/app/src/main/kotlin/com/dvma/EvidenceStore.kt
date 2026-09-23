package com.dvma

/**
 * Process-wide store for cross-app evidence: the last effect an exported
 * component or receiver applied on behalf of an external caller, keyed by a
 * stable string. FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * Several surfaces write here (exported receivers in [BroadcastIpc], exported
 * Activities/Services in [ComponentIpc]) and the Dart side reads it back over a
 * MethodChannel to render the evidence panel. Keeping it in one singleton lets
 * a component started in its own Activity instance report a result that the
 * Flutter engine (a different Activity instance) can still read.
 */
object EvidenceStore {
    const val TAG = "DVMA-EVIDENCE"

    private val applied = mutableMapOf<String, String>()

    @Synchronized
    fun record(key: String, value: String) {
        applied[key] = value
    }

    @Synchronized
    fun read(key: String): String? = applied[key]
}
