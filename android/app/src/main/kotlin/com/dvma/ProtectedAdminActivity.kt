package com.dvma

import android.app.Activity
import android.os.Bundle
import android.util.Log

/**
 * activity_alias_exposure.
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * The protected target. It is declared NOT exported, but a manifest
 * <activity-alias> that IS exported fronts it, so a separate app reaches this
 * guarded screen by starting the alias component. Records the caller when
 * reached through the alias.
 */
class ProtectedAdminActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val caller = callingPackage ?: referrer?.host ?: "unknown"
        val evidence =
            "protected target reached via exported alias by caller=$caller"
        EvidenceStore.record(KEY, evidence)
        Log.w(TAG, evidence)
        finish()
    }

    companion object {
        const val KEY = "activity_alias_exposure"
        private const val TAG = EvidenceStore.TAG
    }
}
