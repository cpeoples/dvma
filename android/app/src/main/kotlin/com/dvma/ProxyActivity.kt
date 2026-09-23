package com.dvma

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log

/**
 * intent_redirection.
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * An exported Activity that extracts a nested "forward" Intent from
 * attacker-supplied extras and starts it with no target validation, letting an
 * external caller reach an internal-only component through DVMA's own identity.
 */
class ProxyActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val caller = callingPackage ?: referrer?.host ?: "unknown"
        // VULN: blindly forward whatever nested intent the caller supplied.
        @Suppress("DEPRECATION")
        val forward: Intent? = intent.getParcelableExtra("forward_intent")
        if (forward != null) {
            EvidenceStore.record(
                KEY,
                "redirected caller=$caller into ${forward.component?.className ?: forward.action} (no validation)",
            )
            forward.setPackage(packageName)
            runCatching { startActivity(forward) }
                .onFailure { Log.w(TAG, "redirect failed: ${it.message}") }
        } else {
            EvidenceStore.record(KEY, "no forward_intent supplied by caller=$caller")
        }
        Log.w(TAG, EvidenceStore.read(KEY) ?: "")
        finish()
    }

    companion object {
        const val KEY = "intent_redirection"
        private const val TAG = EvidenceStore.TAG
    }
}
