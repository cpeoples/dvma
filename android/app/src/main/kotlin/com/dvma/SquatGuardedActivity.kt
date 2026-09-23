package com.dvma

import android.app.Activity
import android.os.Bundle
import android.util.Log

/**
 * custom_signature_permission_squatting (CWE-266 / CWE-277).
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * An exported Activity guarded ONLY by a custom permission declared at
 * protectionLevel="normal". A normal permission is auto-granted to any app that
 * requests it (and the name is squattable by install order), so the guard the
 * developer trusts is trivially obtained. Records that the guarded op ran for
 * the caller.
 */
class SquatGuardedActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val caller = callingPackage ?: referrer?.host ?: "unknown"
        val evidence = "guarded admin op ran for caller=$caller " +
            "(guard is a NORMAL-level custom permission, auto-granted)"
        EvidenceStore.record(KEY, evidence)
        Log.w(TAG, evidence)
        finish()
    }

    companion object {
        const val KEY = "custom_signature_permission_squatting"
        private const val TAG = EvidenceStore.TAG
    }
}
