package com.dvma

import android.app.Activity
import android.os.Bundle
import android.util.Log

/**
 * Internal-only target for intent_redirection.
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * Declared NOT exported. It should only be reachable from inside DVMA, but the
 * exported [ProxyActivity] forwards an attacker-supplied nested intent to it,
 * so it records that it was reached via redirection.
 */
class InternalAdminActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val evidence = "internal-only InternalAdminActivity reached via redirection"
        EvidenceStore.record(ProxyActivity.KEY, evidence)
        Log.w(TAG, evidence)
        finish()
    }

    private companion object {
        const val TAG = EvidenceStore.TAG
    }
}
