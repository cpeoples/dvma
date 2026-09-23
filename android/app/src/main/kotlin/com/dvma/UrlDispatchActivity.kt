package com.dvma

import android.app.Activity
import android.os.Bundle
import android.util.Log

/**
 * exported_component_arbitrary_url_activity
 * (ABEMA CVE-2024-28745 / Samsung Members CVE-2026-20985 & CVE-2025-21079).
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * An exported Activity that reads attacker-supplied extras naming a URL and/or
 * an internal activity and "opens" whatever is named, with DVMA's identity and
 * no allowlist. A separate app supplies the target; DVMA records what it would
 * launch for that external caller.
 */
class UrlDispatchActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val caller = callingPackage ?: referrer?.host ?: "unknown"
        val target = intent.getStringExtra("target") ?: "(none)"
        val activity = intent.getStringExtra("activity") ?: "(none)"
        val evidence =
            "opened target=$target activity=$activity for caller=$caller " +
                "(no allowlist)"
        EvidenceStore.record(KEY, evidence)
        Log.w(TAG, evidence)
        finish()
    }

    companion object {
        const val KEY = "exported_component_arbitrary_url_activity"
        private const val TAG = EvidenceStore.TAG
    }
}
