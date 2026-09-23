package com.dvma

import android.app.Activity
import android.os.Bundle
import android.util.Log

/**
 * confused_deputy_intent_validation
 * (Android Settings CVE-2025-32326 / CVE-2025-32321).
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * A privileged, exported Activity that performs a protected action (writing a
 * secure setting named by an extra) after only checking the requested action
 * string - never the caller's identity or permission. A separate, unprivileged
 * app supplies the setting and DVMA writes it on the caller's behalf.
 */
class DeputyActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val caller = callingPackage ?: referrer?.host ?: "unknown"
        val action = intent.getStringExtra("privileged_action") ?: "(none)"
        val setting = intent.getStringExtra("setting") ?: "(none)"
        // VULN: only the action string is checked; the caller is never verified.
        val evidence = if (action == PRIVILEGED_ACTION) {
            "wrote secure setting '$setting' on behalf of caller=$caller " +
                "(action-only check)"
        } else {
            "ignored: unknown action=$action"
        }
        EvidenceStore.record(KEY, evidence)
        Log.w(TAG, evidence)
        finish()
    }

    companion object {
        const val KEY = "confused_deputy_intent_validation"
        const val PRIVILEGED_ACTION = "com.dvma.action.WRITE_SECURE_SETTING"
        private const val TAG = EvidenceStore.TAG
    }
}
